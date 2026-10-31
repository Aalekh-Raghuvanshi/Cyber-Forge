#!/usr/bin/env python3
"""Deterministic smoke probes for the intentionally vulnerable local benchmark apps.
Run only against the supplied isolated Docker targets. These probes validate the
planted behavior; they are not a substitute for running ZAP or another DAST scanner.
"""
import argparse, json, sys
from pathlib import Path
from urllib.parse import urlencode
import requests

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--app', choices=['app_a', 'app_b'], required=True)
    parser.add_argument('--base-url', default=None)
    parser.add_argument('--output', default=None)
    args = parser.parse_args()
    case_dir = ROOT / 'cases' if args.app == 'app_a' else ROOT / 'ground_truth'
    case_file = case_dir / f'{args.app}_probes.json'
    spec = json.loads(case_file.read_text(encoding='utf-8'))
    base = (args.base_url or spec['base_url']).rstrip('/')
    results = []
    for probe in spec['probes']:
        params = {probe['parameter']: probe['payload']}
        url = base + probe['path']
        try:
            response = requests.get(url, params=params, timeout=4, allow_redirects=False)
            assertion = probe['assertion']
            body = response.text
            passed = False
            evidence = f'HTTP {response.status_code}'
            if assertion == 'json_array_length_greater_than_1':
                try:
                    body_json = response.json()
                    passed = isinstance(body_json, list) and len(body_json) > 1
                    evidence += f'; returned_rows={len(body_json) if isinstance(body_json, list) else "not-list"}'
                except Exception:
                    evidence += '; response was not JSON'
            elif assertion.startswith('body_contains:'):
                marker = assertion.split(':', 1)[1]
                passed = marker in body
                evidence += f'; marker_present={passed}'
            elif assertion == '302_location_starts_https_example_invalid':
                location = response.headers.get('Location', '')
                passed = response.status_code in (301, 302, 303, 307, 308) and location.startswith('https://example.invalid/')
                evidence += f'; location={location!r}'
            results.append({
                'case_id': probe['case_id'], 'path': probe['path'], 'parameter': probe['parameter'],
                'type': probe['type'], 'cwe': probe['cwe'], 'passed': passed, 'evidence': evidence
            })
        except requests.RequestException as exc:
            results.append({'case_id': probe['case_id'], 'path': probe['path'], 'parameter': probe['parameter'],
                            'type': probe['type'], 'cwe': probe['cwe'], 'passed': False, 'evidence': str(exc)})
    passed = sum(1 for x in results if x['passed'])
    report = {'app': args.app, 'base_url': base, 'total': len(results), 'passed': passed,
              'failed': len(results)-passed, 'results': results}
    rendered = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(rendered, encoding='utf-8')
    print(rendered)
    return 0 if passed == len(results) else 1

if __name__ == '__main__':
    sys.exit(main())
