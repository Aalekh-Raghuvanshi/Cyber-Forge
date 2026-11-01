#!/usr/bin/env python3
"""Run OWASP BenchmarkPython against local ZAP and Cyber-Forge; score by testcase."""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx


BENCHMARK_DIR = Path("/benchmark-python")
OUTPUT_DIR = Path("/benchmark-results")
CASE_PATTERN = re.compile(r"BenchmarkTest\d{5}", re.IGNORECASE)
HTTP_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
ZAP_BENCHMARK_POLICY = "Default Policy"


def read_answer_key(path: Path) -> dict[str, dict[str, Any]]:
    with path.open(newline="", encoding="utf-8-sig") as stream:
        rows = csv.reader(stream)
        header = [column.strip().lstrip("# ").lower() for column in next(rows)]
        key: dict[str, dict[str, Any]] = {}
        for row in rows:
            if len(row) < 4:
                continue
            values = dict(zip(header, (item.strip() for item in row)))
            name = values.get("test name", "")
            if name:
                key[name] = {
                    "category": values.get("category", ""),
                    "vulnerable": values.get("real vulnerability", "").lower() == "true",
                    "cwe": normalize_cwe(values.get("cwe", "")),
                }
    return key


def select_stratified_sample(
    cases: dict[str, dict[str, Any]], per_category: int, seed: int
) -> dict[str, dict[str, Any]]:
    """Select a repeatable, balanced sample of true and false cases per category."""
    grouped: dict[str, dict[bool, list[str]]] = {}
    for case_id, expected in cases.items():
        grouped.setdefault(expected["category"], {True: [], False: []})[
            expected["vulnerable"]
        ].append(case_id)

    selected: dict[str, dict[str, Any]] = {}
    for category_index, category in enumerate(sorted(grouped)):
        truth_groups = grouped[category]
        rng = random.Random(seed + category_index)
        target = min(per_category, len(truth_groups[True]) + len(truth_groups[False]))
        positive_target = (target + 1) // 2
        negative_target = target // 2
        positives = sorted(truth_groups[True])
        negatives = sorted(truth_groups[False])
        picked_positive = rng.sample(positives, min(positive_target, len(positives)))
        picked_negative = rng.sample(negatives, min(negative_target, len(negatives)))
        picked = picked_positive + picked_negative
        remaining = sorted(set(positives + negatives) - set(picked))
        if len(picked) < target:
            picked.extend(rng.sample(remaining, target - len(picked)))
        for case_id in picked:
            selected[case_id] = cases[case_id]
    return selected


def normalize_cwe(value: Any) -> str:
    digits = re.search(r"\d+", str(value or ""))
    return str(int(digits.group())) if digits else ""


def metric(cases: dict[str, dict[str, Any]], detected: set[str]) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for case_id, expected in cases.items():
        actual = case_id.upper() in detected
        if expected["vulnerable"] and actual:
            tp += 1
        elif expected["vulnerable"]:
            fn += 1
        elif actual:
            fp += 1
        else:
            tn += 1
    tpr = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "TPR": round(tpr, 6),
        "FPR": round(fpr, 6),
        "Youden_J": round(tpr - fpr, 6),
    }


def finding_cases(findings: list[dict[str, Any]], cases: dict[str, dict[str, Any]], *,
                  location_fields: tuple[str, ...], require_expected_cwe: bool) -> set[str]:
    found: set[str] = set()
    case_lookup = {case_id.upper(): expected for case_id, expected in cases.items()}
    for finding in findings:
        location = " ".join(str(finding.get(field) or "") for field in location_fields)
        cwe = normalize_cwe(finding.get("cwe_id") or finding.get("cweid"))
        for case_id in CASE_PATTERN.findall(location):
            case_id = case_id.upper()
            expected = case_lookup.get(case_id)
            if expected and (not require_expected_cwe or cwe == expected["cwe"]):
                found.add(case_id)
    return found


def score_set(findings: list[dict[str, Any]], cases: dict[str, dict[str, Any]],
              location_fields: tuple[str, ...]) -> dict[str, Any]:
    any_hit = finding_cases(findings, cases, location_fields=location_fields,
                            require_expected_cwe=False)
    cwe_hit = finding_cases(findings, cases, location_fields=location_fields,
                            require_expected_cwe=True)
    return {
        "case_detection": metric(cases, any_hit),
        "expected_cwe_detection": metric(cases, cwe_hit),
        "cases_with_any_finding": len(any_hit),
        "cases_with_expected_cwe": len(cwe_hit),
        "unmapped_findings": sum(
            not CASE_PATTERN.search(" ".join(str(item.get(field) or "") for field in location_fields))
            for item in findings
        ),
    }


def zap_get(api: str, endpoint: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    response = httpx.get(f"{api.rstrip('/')}/JSON/{endpoint}", params=params or {}, timeout=30)
    response.raise_for_status()
    return response.json()


def wait_for_zap_scan(api: str, kind: str, scan_id: str, timeout: int) -> None:
    endpoint = f"{kind}/view/status/"
    started = time.monotonic()
    last = -1
    connection_failures = 0
    while time.monotonic() - started < timeout:
        try:
            data = zap_get(api, endpoint, {"scanId": scan_id})
            connection_failures = 0
        except httpx.ConnectError as error:
            connection_failures += 1
            if connection_failures >= 6:
                raise RuntimeError(
                    f"ZAP API at {api} stayed unreachable for 30 seconds during {kind} scan "
                    f"{scan_id}; the scanner container may have stopped (often due to memory pressure)."
                ) from error
            time.sleep(5)
            continue
        progress = int(data.get("status", 0))
        if progress != last:
            print(f"{kind} scan {scan_id}: {progress}%", flush=True)
            last = progress
        if progress >= 100:
            return
        time.sleep(3)
    raise TimeoutError(f"ZAP {kind} scan {scan_id} exceeded {timeout} seconds")


def configure_focused_zap_scan(api: str) -> list[dict[str, str]]:
    """Keep the benchmark scan broad enough for its injection cases but bounded."""
    scanner_data = zap_get(api, "ascan/view/scanners/")
    scanners = scanner_data.get("scanners", [])
    relevant_terms = (
        "path traversal", "file inclusion", "cross site scripting", "sql injection",
        "command injection", "xml external entity", "server side include",
        "external redirect", "code injection", "template injection", "ldap injection",
        "xpath injection", "server side request forgery", "ssrf", "deserialization",
    )
    selected = []
    for scanner in scanners:
        name = str(scanner.get("name", ""))
        lowered = name.lower()
        if ("dom" in lowered or "client side" in lowered or "persistent" in lowered
                or "time based" in lowered or "blind" in lowered):
            continue
        if any(term in lowered for term in relevant_terms):
            selected.append({"id": str(scanner.get("id")), "name": name})
    if not selected:
        raise RuntimeError("ZAP returned no active scanner rules matching the focused benchmark profile")

    policy_params = {"scanPolicyName": ZAP_BENCHMARK_POLICY}
    zap_get(api, "ascan/action/updateScanPolicy/", {
        **policy_params,
        "alertThreshold": "MEDIUM",
        "attackStrength": "LOW",
    })
    zap_get(api, "ascan/action/disableAllScanners/", policy_params)
    zap_get(api, "ascan/action/enableScanners/", {
        "ids": ",".join(scanner["id"] for scanner in selected),
        **policy_params,
    })
    zap_get(api, "ascan/action/setOptionThreadPerHost/", {"Integer": 2})
    zap_get(api, "ascan/action/setOptionMaxScanDurationInMins/", {"Integer": 120})
    zap_get(api, "ascan/action/setOptionMaxRuleDurationInMins/", {"Integer": 15})
    return selected


def wait_for_passive_scan(api: str, timeout: int = 600) -> None:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        result = zap_get(api, "pscan/view/recordsToScan/")
        pending = int(result.get("recordsToScan", 0))
        if pending <= 0:
            print("ZAP passive scan queue is clear", flush=True)
            return
        print(f"Waiting for {pending} passive scan records", flush=True)
        time.sleep(5)
    raise TimeoutError(f"ZAP passive scan queue did not clear within {timeout} seconds")


def xml_parameters(case: ET.Element, tag: str) -> dict[str, str]:
    return {item.attrib["name"]: item.attrib.get("value", "")
            for item in case.findall(tag) if item.attrib.get("name")}


def safe_header_value(value: str) -> str:
    """Percent-encode HTTP-forbidden control bytes in corpus header values."""
    encoded = []
    for char in value:
        codepoint = ord(char)
        if codepoint < 32 or codepoint == 127:
            encoded.append(f"%{codepoint:02X}")
        elif codepoint > 255:
            encoded.extend(f"%{byte:02X}" for byte in char.encode("utf-8"))
        else:
            encoded.append(char)
    return "".join(encoded)


def replay_cases(crawler: Path, cases: dict[str, dict[str, Any]], proxy: str) -> dict[str, Any]:
    tree = ET.parse(crawler)
    root = tree.getroot()
    context = ssl._create_unverified_context()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
        urllib.request.HTTPSHandler(context=context),
    )
    totals = Counter()
    skipped_invalid_header_cases: set[str] = set()
    entries = [entry for entry in root if entry.attrib.get("tcName") in cases]
    for index, case in enumerate(entries, start=1):
        case_id = case.attrib.get("tcName", "")
        source_url = case.attrib.get("URL", "")
        parsed = urllib.parse.urlsplit(source_url)
        path = parsed.path
        url = f"https://benchmark:8443{path}"
        get_params = xml_parameters(case, "getparam")
        form_params = xml_parameters(case, "formparam")
        headers = {}
        for item in case.findall("header"):
            header_name = item.attrib.get("name", "")
            if not header_name:
                continue
            if not HTTP_HEADER_NAME.fullmatch(header_name):
                skipped_invalid_header_cases.add(case_id)
                continue
            headers[header_name] = safe_header_value(item.attrib.get("value", ""))
        cookies = xml_parameters(case, "cookie")
        if cookies:
            headers["Cookie"] = "; ".join(
                f"{name}={safe_header_value(value)}" for name, value in cookies.items()
            )
        for method, params in (("GET", get_params), ("POST", form_params)):
            request_url = url
            data: bytes | None = None
            request_headers = {"User-Agent": "CyberForge-OWASP-Benchmark-Harness/1.0", **headers}
            if method == "GET" and params:
                request_url += "?" + urllib.parse.urlencode(params)
            elif method == "POST":
                if get_params:
                    request_url += "?" + urllib.parse.urlencode(get_params)
                data = urllib.parse.urlencode(params).encode() if params else b""
                request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            request = urllib.request.Request(request_url, data=data,
                                            headers=request_headers, method=method)
            try:
                with opener.open(request, timeout=8) as response:
                    response.read(256)
                    totals[f"{method}_requests"] += 1
                    if response.status < 500:
                        totals["responses_below_500"] += 1
            except urllib.error.HTTPError as error:
                totals[f"{method}_requests"] += 1
                if error.code < 500:
                    totals["responses_below_500"] += 1
            except Exception as error:
                totals["request_errors"] += 1
                if totals["request_errors"] <= 10:
                    print(f"Replay issue for {case_id} {method}: {error}", flush=True)
        if index % 100 == 0 or index == len(entries):
            print(f"Replayed {index}/{len(entries)} testcase pairs", flush=True)
    return {
        **dict(totals),
        "cases_with_unreplayable_header_names": len(skipped_invalid_header_cases),
        "unreplayable_header_case_ids": sorted(skipped_invalid_header_cases),
    }


def scan_sample_cases(api: str, crawler: Path, cases: dict[str, dict[str, Any]],
                      target: str, timeout: int) -> list[str]:
    """Active-scan only the sampled case URLs and their declared GET/POST vectors."""
    root = ET.parse(crawler).getroot()
    entries = [entry for entry in root if entry.attrib.get("tcName") in cases]
    completed: list[str] = []
    target_origin = target.rstrip("/")
    for index, case in enumerate(entries, start=1):
        case_id = case.attrib["tcName"]
        source_url = urllib.parse.urlsplit(case.attrib["URL"])
        base_url = target_origin + source_url.path
        get_params = xml_parameters(case, "getparam")
        form_params = xml_parameters(case, "formparam")
        query = urllib.parse.urlencode(get_params)
        get_url = base_url + ("?" + query if query else "")

        requests_to_scan = [("GET", get_url, "")]
        if form_params:
            requests_to_scan.append(("POST", get_url, urllib.parse.urlencode(form_params)))

        for method, url, post_data in requests_to_scan:
            result = zap_get(api, "ascan/action/scan/", {
                "url": url,
                "recurse": "false",
                "inScopeOnly": "false",
                "scanPolicyName": ZAP_BENCHMARK_POLICY,
                "method": method,
                "postData": post_data,
            })
            scan_id = str(result.get("scan", "0"))
            wait_for_zap_scan(api, "ascan", scan_id, timeout)
        completed.append(case_id)
        if index % 10 == 0 or index == len(entries):
            print(f"Actively scanned {index}/{len(entries)} sampled testcases", flush=True)
    return completed


def get_zap_alerts(api: str, target: str) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    start = 0
    page_size = 5000
    while True:
        result = zap_get(api, "core/view/alerts/", {
            "baseurl": target,
            "start": start,
            "count": page_size,
        })
        page = result.get("alerts", [])
        alerts.extend(page)
        if len(page) < page_size:
            return alerts
        start += len(page)


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://benchmark:8443")
    parser.add_argument("--zap-api", default="http://127.0.0.1:8090")
    parser.add_argument("--cyberforge-api", default="http://127.0.0.1:8001")
    parser.add_argument("--scan-timeout", type=int, default=7200)
    parser.add_argument("--cases-per-category", type=int, default=10)
    parser.add_argument("--sample-seed", type=int, default=20261101)
    args = parser.parse_args()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    full_cases = read_answer_key(BENCHMARK_DIR / "expectedresults-0.1.csv")
    if args.cases_per_category < 2:
        parser.error("--cases-per-category must be at least 2 to sample both truth classes")
    cases = select_stratified_sample(full_cases, args.cases_per_category, args.sample_seed)
    category_counts = Counter(case["category"] for case in cases.values())
    category_truth_counts = {
        category: {
            "sampled": sum(item["category"] == category for item in cases.values()),
            "vulnerable": sum(item["category"] == category and item["vulnerable"] for item in cases.values()),
            "not_vulnerable": sum(item["category"] == category and not item["vulnerable"] for item in cases.values()),
        }
        for category in sorted(category_counts)
    }
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()

    print(
        f"Selected {len(cases)} of {len(full_cases)} OWASP BenchmarkPython v0.1 cases "
        f"across {len(category_counts)} categories ({args.cases_per_category} per category target)",
        flush=True,
    )
    write_json(OUTPUT_DIR / "sampled-cases.json", {
        "seed": args.sample_seed,
        "requested_cases_per_category": args.cases_per_category,
        "full_suite_cases": len(full_cases),
        "sampled_cases": len(cases),
        "category_counts": category_truth_counts,
        "cases": [
            {"test_id": case_id, **expected}
            for case_id, expected in sorted(cases.items())
        ],
    })
    zap_get(args.zap_api, "core/action/newSession/", {
        "name": "cyberforge-benchmark", "overwrite": "true",
    })
    print("Started a clean session in the dedicated benchmark ZAP", flush=True)
    print("Replaying the official testcase request definitions through ZAP ...", flush=True)
    replay_stats = replay_cases(
        BENCHMARK_DIR / "data/benchmark-crawler-http.xml", cases, args.zap_api
    )
    write_json(OUTPUT_DIR / "replay.json", replay_stats)

    wait_for_passive_scan(args.zap_api)
    zap_profile = configure_focused_zap_scan(args.zap_api)
    print("Focused ZAP active scan rules: " + ", ".join(
        f"{rule['id']} {rule['name']}" for rule in zap_profile
    ), flush=True)
    print(f"Starting targeted active scans for {len(cases)} sampled testcases", flush=True)
    scanned_case_ids = scan_sample_cases(
        args.zap_api,
        BENCHMARK_DIR / "data/benchmark-crawler-http.xml",
        cases,
        args.target,
        args.scan_timeout,
    )

    alerts = get_zap_alerts(args.zap_api, args.target)
    write_json(OUTPUT_DIR / "zap-alerts.json", alerts)
    print(f"Retrieved {len(alerts)} ZAP alerts scoped to the benchmark", flush=True)

    api = args.cyberforge_api.rstrip("/")
    with httpx.Client(timeout=httpx.Timeout(3600)) as client:
        dast_response = client.post(f"{api}/api/dast/scan", json={
            "target_url": args.target,
            "raw_zap_alerts": alerts,
        })
        dast_response.raise_for_status()
        dast_result = dast_response.json()
        write_json(OUTPUT_DIR / "cyberforge-dast.json", dast_result)

        print(f"Running Cyber-Forge SAST on the same {len(cases)} sampled testcase files ...", flush=True)
        source_files = []
        for case_id in cases:
            source_path = BENCHMARK_DIR / "testcode" / f"{case_id}.py"
            source_files.append({
                "filename": f"testcode/{case_id}.py",
                "content": source_path.read_text(encoding="utf-8"),
            })
        sast_response = client.post(f"{api}/api/sast/scan", json={
            "files": source_files,
            "generate_fixes": False,
        })
        sast_response.raise_for_status()
        sast_result = sast_response.json()
        write_json(OUTPUT_DIR / "cyberforge-sast.json", sast_result)

    zap_score = score_set(alerts, cases, ("url", "uri"))
    dast_findings = dast_result.get("findings", [])
    dast_score = score_set(dast_findings, cases, ("url_path", "url", "description", "evidence"))
    sast_findings = sast_result.get("findings", [])
    sast_score = score_set(sast_findings, cases, ("file", "code_snippet", "description"))
    combined_findings = alerts + dast_findings + sast_findings
    combined_score = score_set(combined_findings, cases,
                               ("url", "uri", "url_path", "file", "code_snippet", "description"))

    report = {
        "benchmark": "OWASP BenchmarkPython",
        "benchmark_version": "0.1",
        "full_suite_testcases": len(full_cases),
        "sampled_testcases": len(cases),
        "categories_sampled": len(category_counts),
        "sample_seed": args.sample_seed,
        "category_counts": category_truth_counts,
        "actively_scanned_case_ids": scanned_case_ids,
        "started_at_utc": started_at,
        "duration_seconds": round(time.monotonic() - started, 2),
        "target_url": args.target,
        "zap_active_scan_profile": {
            "name": "Benchmark-focused low-strength",
            "thread_per_host": 2,
            "max_scan_minutes": 120,
            "max_rule_minutes": 15,
            "rules": zap_profile,
        },
        "replay": replay_stats,
        "counts": {
            "zap_alerts": len(alerts),
            "cyberforge_dast_findings": len(dast_findings),
            "cyberforge_sast_findings": len(sast_findings),
            "sast_files_scanned": sast_result.get("scanned_files_count"),
        },
        "scores": {
            "zap_raw": zap_score,
            "cyberforge_dast": dast_score,
            "cyberforge_sast": sast_score,
            "combined_case_evidence": combined_score,
        },
        "scoring_note": (
            "Metrics apply only to the deterministic category-stratified sample, not the full OWASP suite. "
            "Case detection counts a testcase when a finding location identifies its BenchmarkTest ID. "
            "Expected-CWE detection additionally requires exact CWE agreement with expectedresults-0.1.csv. "
            "Findings without testcase IDs are reported as unmapped and excluded from testcase confusion metrics."
        ),
    }
    write_json(OUTPUT_DIR / "score.json", report)
    with (OUTPUT_DIR / "summary.md").open("w", encoding="utf-8") as out:
        out.write("# OWASP BenchmarkPython v0.1 results\n\n")
        out.write(f"- Sampled testcases: {len(cases)} of {len(full_cases)}\n")
        out.write(f"- Categories: {len(category_counts)}; {args.cases_per_category} per category target\n")
        out.write(f"- Seed: {args.sample_seed}\n- Target: `{args.target}`\n")
        out.write(f"- Duration: {report['duration_seconds']} seconds\n")
        out.write(f"- Replay: {replay_stats}\n\n")
        out.write("| Scanner | Metric | TP | FP | TN | FN | TPR | FPR | Youden J |\n")
        out.write("|---|---|---:|---:|---:|---:|---:|---:|---:|\n")
        for label, result in (("ZAP raw", zap_score), ("Cyber-Forge DAST", dast_score),
                              ("Cyber-Forge SAST", sast_score)):
            for metric_name in ("case_detection", "expected_cwe_detection"):
                scores = result[metric_name]
                out.write(f"| {label} | {metric_name} | {scores['TP']} | {scores['FP']} | "
                          f"{scores['TN']} | {scores['FN']} | {scores['TPR']} | "
                          f"{scores['FPR']} | {scores['Youden_J']} |\n")
    print("Benchmark run and scoring completed. Results are in /benchmark-results.", flush=True)
    print(json.dumps(report["scores"], indent=2), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"Benchmark run failed: {error}", file=sys.stderr, flush=True)
        raise
