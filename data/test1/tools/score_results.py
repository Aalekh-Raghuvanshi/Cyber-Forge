#!/usr/bin/env python3
"""Score normalized SAST/DAST/correlation output against the benchmark answer key."""
import argparse, json
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]

def get_path(obj):
    value = obj.get('path') or obj.get('url') or obj.get('endpoint') or ''
    if value.startswith('http://') or value.startswith('https://'):
        return urlparse(value).path
    return value.split('?', 1)[0]

def get_param(obj):
    return obj.get('parameter') or obj.get('param') or obj.get('input_vector') or ''

def get_file(obj):
    return (obj.get('file') or obj.get('source_file') or '').replace('\\','/')

def get_line(obj):
    value = obj.get('line') or obj.get('start_line') or obj.get('source_line')
    if value is None and isinstance(obj.get('location'), dict):
        value = obj['location'].get('line') or obj['location'].get('start_line')
    try: return int(value)
    except (TypeError, ValueError): return None

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--app', choices=['app_a','app_b'], required=True)
    p.add_argument('--results', required=True, help='Path to normalized result JSON')
    args = p.parse_args()
    answer = json.loads((ROOT/'ground_truth'/'answer_key.json').read_text(encoding='utf-8'))['apps'][args.app]
    predicted = json.loads(Path(args.results).read_text(encoding='utf-8'))
    planted = answer['planted_pairs']
    decoys = answer['safe_decoys']

    code_lookup = {(x['file'], x['line']): x['case_id'] for x in planted}
    runtime_lookup = {(x['method'], x['path'], x['parameter']): x['case_id'] for x in planted}
    decoy_code = {(x['file'], x['line']) for x in decoys if x.get('line') is not None}
    decoy_runtime = {(x['method'], x['path'], x['parameter']) for x in decoys}

    code_found = set()
    for finding in predicted.get('code_findings', []):
        key = (get_file(finding), get_line(finding))
        if key in code_lookup:
            case_id = code_lookup[key]
            cwe = finding.get('cwe')
            if not cwe or cwe == next(x['cwe'] for x in planted if x['case_id']==case_id):
                code_found.add(case_id)
    runtime_found = set()
    for finding in predicted.get('runtime_findings', []):
        key = (str(finding.get('method','GET')).upper(), get_path(finding), get_param(finding))
        if key in runtime_lookup:
            case_id = runtime_lookup[key]
            cwe = finding.get('cwe')
            if not cwe or cwe == next(x['cwe'] for x in planted if x['case_id']==case_id):
                runtime_found.add(case_id)

    correct = set()
    wrong = 0
    confirmed = predicted.get('confirmed_issues', [])
    for issue in confirmed:
        sast = issue.get('sast') or issue.get('code') or {}
        dast = issue.get('dast') or issue.get('runtime') or {}
        sast_key = (get_file(sast), get_line(sast))
        dast_key = (str(dast.get('method','GET')).upper(), get_path(dast), get_param(dast))
        sid = code_lookup.get(sast_key)
        did = runtime_lookup.get(dast_key)
        if sid and did and sid == did:
            correct.add(sid)
        elif sid and did and sid != did:
            wrong += 1

    reports = predicted.get('reported_issues', [])
    false_alarm_count = 0
    for issue in reports:
        file_key = (get_file(issue), get_line(issue))
        runtime_key = (str(issue.get('method','GET')).upper(), get_path(issue), get_param(issue))
        if file_key in decoy_code or runtime_key in decoy_runtime:
            false_alarm_count += 1

    total = len(planted)
    reported_count = len(reports)
    confirmed_count = len(confirmed)
    scan_seconds = predicted.get('scan_seconds')
    def pct(n, d): return round((100.0*n/d), 2) if d else None
    metrics = {
        'app': args.app,
        'role': answer['role'],
        'positive_pairs': total,
        'code_detection_pct': pct(len(code_found), total),
        'code_detection_count': len(code_found),
        'runtime_detection_pct': pct(len(runtime_found), total),
        'runtime_detection_count': len(runtime_found),
        'correct_links_pct': pct(len(correct), total),
        'correct_links_count': len(correct),
        'wrong_links_pct': pct(wrong, confirmed_count),
        'wrong_links_count': wrong,
        'confirmed_issues_count': confirmed_count,
        'false_alarms_pct': pct(false_alarm_count, reported_count),
        'false_alarm_count': false_alarm_count,
        'reported_issues_count': reported_count,
        'unseen_app_pct': pct(len(correct), total) if args.app == 'app_b' else None,
        'scan_seconds': scan_seconds,
        'targets': {
            'good': {'code_detection': '>60%', 'runtime_detection': '>50%', 'correct_links': '>50%', 'wrong_links': '<20%', 'false_alarms': '<30%', 'unseen_app': '>40%', 'runtime': '<15 min'},
            'great': {'code_detection': '>85%', 'runtime_detection': '>80%', 'correct_links': '>80%', 'wrong_links': '<5%', 'false_alarms': '<10%', 'unseen_app': '>65%', 'runtime': '<5 min'}
        },
        'missed_code_cases': sorted(set(x['case_id'] for x in planted)-code_found),
        'missed_runtime_cases': sorted(set(x['case_id'] for x in planted)-runtime_found),
        'unlinked_cases': sorted(set(x['case_id'] for x in planted)-correct)
    }
    print(json.dumps(metrics, indent=2))

if __name__ == '__main__':
    main()
