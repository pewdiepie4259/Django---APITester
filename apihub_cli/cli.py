#!/usr/bin/env python3
import sys
import os
import json
import argparse
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET

CONFIG_FILE = os.path.expanduser("~/.apihub_config.json")


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "url": os.environ.get("APIHUB_URL", "http://127.0.0.1:8000"),
        "token": os.environ.get("APIHUB_TOKEN", "")
    }


def save_config(cfg):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save CLI config: {e}", file=sys.stderr)


def api_request(endpoint, method="GET", data=None, config=None):
    if not config:
        config = load_config()

    base_url = config.get("url", "http://127.0.0.1:8000").rstrip('/')
    token = config.get("token", "")

    url = f"{base_url}{endpoint}"
    req = urllib.request.Request(url, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    body_bytes = None
    if data is not None:
        body_bytes = json.dumps(data).encode('utf-8')

    try:
        with urllib.request.urlopen(req, data=body_bytes, timeout=30) as resp:
            resp_body = resp.read().decode('utf-8')
            return json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as e:
        err_text = e.read().decode('utf-8')
        try:
            err_json = json.loads(err_text)
            msg = err_json.get("error") or err_text
        except Exception:
            msg = err_text
        return {"error": f"HTTP {e.code}: {msg}", "_status_code": e.code}
    except Exception as e:
        return {"error": f"Connection error: {str(e)}", "_status_code": 500}


def cmd_auth_login(args):
    cfg = load_config()
    if args.url:
        cfg["url"] = args.url.rstrip('/')
    if args.token:
        cfg["token"] = args.token
    else:
        print(f"APIHub Target URL: {cfg['url']}")
        tok = input("Enter Personal Access Token (ahp_...): ").strip()
        if not tok:
            print("Error: Personal Access Token is required.", file=sys.stderr)
            sys.exit(2)
        cfg["token"] = tok

    save_config(cfg)
    # Validate token
    res = api_request("/api/workspaces/", config=cfg)
    if "error" in res:
        print(f"❌ Login verification failed: {res['error']}", file=sys.stderr)
        sys.exit(2)

    print(f"✅ Successfully authenticated with APIHub at {cfg['url']}")
    sys.exit(0)


def cmd_auth_logout(args):
    cfg = load_config()
    cfg["token"] = ""
    save_config(cfg)
    print("✅ Logged out from APIHub CLI.")
    sys.exit(0)


def cmd_workspaces_list(args):
    res = api_request("/api/workspaces/")
    if "error" in res:
        print(f"Error: {res['error']}", file=sys.stderr)
        sys.exit(2)

    workspaces = res.get("workspaces", [])
    if args.format == "json":
        print(json.dumps(workspaces, indent=2))
        sys.exit(0)

    print("\nAPIHUB WORKSPACES")
    print("=" * 50)
    for w in workspaces:
        p_tag = " (Personal)" if w.get("is_personal") else ""
        print(f" ID: {w['id']} | Name: {w['name']}{p_tag} | Role: {w.get('user_role', 'MEMBER')}")
    print()
    sys.exit(0)


def cmd_collections_list(args):
    res = api_request("/api/collections/")
    if "error" in res:
        print(f"Error: {res['error']}", file=sys.stderr)
        sys.exit(2)

    collections = res.get("collections", [])
    if args.format == "json":
        print(json.dumps(collections, indent=2))
        sys.exit(0)

    print("\nAPIHUB COLLECTIONS")
    print("=" * 50)
    for c in collections:
        reqs_cnt = len(c.get("saved_requests", []))
        print(f" ID: {c['id']} | Name: {c['name']} | Requests: {reqs_cnt}")
    print()
    sys.exit(0)


def cmd_requests_run(args):
    req_id = args.id
    res = api_request(f"/api/requests/{req_id}/")
    if "error" in res:
        print(f"Error: {res['error']}", file=sys.stderr)
        sys.exit(2)

    s_req = res.get("request", {})
    payload = {
        "method": s_req.get("method", "GET"),
        "url": s_req.get("url", ""),
        "headers": s_req.get("headers", []),
        "params": s_req.get("params", []),
        "body": s_req.get("body", ""),
        "tests": s_req.get("tests", []),
        "contract_schema": s_req.get("contract_schema", {})
    }

    exec_res = api_request("/api/execute/", method="POST", data=payload)
    if "error" in exec_res:
        print(f"Execution Error: {exec_res['error']}", file=sys.stderr)
        sys.exit(2)

    if args.format == "json":
        print(json.dumps(exec_res, indent=2))
        sys.exit(0)

    status_code = exec_res.get("status_code", 500)
    latency = exec_res.get("time_ms", 0.0)

    print("\nAPIHUB REQUEST RUN")
    print("=" * 50)
    print(f" Request: {s_req.get('name')} ({s_req.get('method')} {s_req.get('url')})")
    print(f" Status:  {status_code}")
    print(f" Latency: {latency:.1f}ms")

    eval_results = exec_res.get("eval_results", [])
    passed = sum(1 for r in eval_results if r.get("passed"))
    failed = sum(1 for r in eval_results if not r.get("passed"))
    print(f" Tests:   {passed} passed, {failed} failed")

    sys.exit(0 if failed == 0 and status_code < 400 else 1)


def cmd_tests_run(args):
    suite_id = args.suite
    res = api_request(f"/api/test-suites/{suite_id}/run/", method="POST")
    if "error" in res:
        print(f"Error: {res['error']}", file=sys.stderr)
        sys.exit(2)

    suite_run = res.get("suite_run", {})
    total = suite_run.get("total_tests", 0)
    passed = suite_run.get("passed_tests", 0)
    failed = suite_run.get("failed_tests", 0)
    contract_passed = suite_run.get("contract_passed", True)
    details = suite_run.get("details", [])

    if args.format == "json":
        output = {
            "status": "passed" if (failed == 0 and contract_passed) else "failed",
            "suite_id": suite_id,
            "total_tests": total,
            "passed_tests": passed,
            "failed_tests": failed,
            "contract_passed": contract_passed,
            "duration_ms": suite_run.get("duration_ms", 0.0),
            "details": details
        }
        print(json.dumps(output, indent=2))
        sys.exit(0 if (failed == 0 and contract_passed) else 1)

    elif args.format == "junit":
        testsuite_elem = ET.Element("testsuite", {
            "name": f"TestSuite_{suite_id}",
            "tests": str(total),
            "failures": str(failed),
            "time": str(round(suite_run.get("duration_ms", 0.0) / 1000.0, 3))
        })
        for item in details:
            case_elem = ET.SubElement(testsuite_elem, "testcase", {
                "name": item.get("request_name", "Endpoint Test"),
                "classname": f"APIHub.{item.get('method', 'GET')}",
                "time": str(round(item.get("latency_ms", 0.0) / 1000.0, 3))
            })
            if not item.get("assertions_passed") or not item.get("contract_passed"):
                fail_elem = ET.SubElement(case_elem, "failure", {"message": "Assertion or Contract check failed"})
                fail_elem.text = json.dumps(item.get("assertion_results", []))

        xml_str = ET.tostring(testsuite_elem, encoding="utf-8").decode("utf-8")
        print('<?xml version="1.0" encoding="UTF-8"?>')
        print(xml_str)
        sys.exit(0 if (failed == 0 and contract_passed) else 1)

    # Default Text Output
    print(f"\nAPIHUB TEST SUITE RUN: {suite_run.get('suite_name', suite_id)}")
    print("=" * 50)
    for item in details:
        icon = "✓" if (item.get("assertions_passed") and item.get("contract_passed")) else "✕"
        print(f" {icon} {item.get('method')} {item.get('request_name')} [{item.get('status_code')}] ({item.get('latency_ms')}ms)")

    print("-" * 50)
    print(f" Summary: {passed} passed, {failed} failed | Contract: {'✓ Passed' if contract_passed else '✕ Violation'}")
    print(f" Duration: {suite_run.get('duration_ms', 0.0):.1f}ms")

    sys.exit(0 if (failed == 0 and contract_passed) else 1)


def main():
    parser = argparse.ArgumentParser(prog="apihub", description="APIHub CLI — Developer API Testing & CI/CD Tool")
    subparsers = parser.add_subparsers(dest="subcommand", help="Available Commands")

    # Auth
    p_auth = subparsers.add_parser("auth", help="Authentication commands")
    p_auth_sub = p_auth.add_subparsers(dest="auth_action")
    p_login = p_auth_sub.add_parser("login", help="Authenticate CLI with token")
    p_login.add_argument("--url", help="APIHub Base URL")
    p_login.add_argument("--token", help="Personal Access Token (ahp_...)")
    p_logout = p_auth_sub.add_parser("logout", help="Log out from CLI")

    # Workspaces
    p_ws = subparsers.add_parser("workspace", help="Workspace commands")
    p_ws_sub = p_ws.add_subparsers(dest="ws_action")
    p_ws_list = p_ws_sub.add_parser("list", help="List workspaces")
    p_ws_list.add_argument("--format", choices=["text", "json"], default="text")

    # Collections
    p_col = subparsers.add_parser("collections", help="Collection commands")
    p_col_sub = p_col.add_subparsers(dest="col_action")
    p_col_list = p_col_sub.add_parser("list", help="List collections")
    p_col_list.add_argument("--format", choices=["text", "json"], default="text")

    # Requests
    p_req = subparsers.add_parser("requests", help="Saved Request commands")
    p_req_sub = p_req.add_subparsers(dest="req_action")
    p_req_run = p_req_sub.add_parser("run", help="Execute a saved request")
    p_req_run.add_argument("id", help="Saved Request ID")
    p_req_run.add_argument("--format", choices=["text", "json"], default="text")

    # Tests
    p_tests = subparsers.add_parser("tests", help="Test Suite execution")
    p_tests_sub = p_tests.add_subparsers(dest="tests_action")
    p_tests_run = p_tests_sub.add_parser("run", help="Run a test suite")
    p_tests_run.add_argument("suite", help="Test Suite ID")
    p_tests_run.add_argument("--format", choices=["text", "json", "junit"], default="text")

    args = parser.parse_args()

    if args.subcommand == "auth":
        if args.auth_action == "login":
            cmd_auth_login(args)
        elif args.auth_action == "logout":
            cmd_auth_logout(args)
        else:
            p_auth.print_help()
    elif args.subcommand == "workspace":
        if args.ws_action == "list":
            cmd_workspaces_list(args)
        else:
            p_ws.print_help()
    elif args.subcommand == "collections":
        if args.col_action == "list":
            cmd_collections_list(args)
        else:
            p_col.print_help()
    elif args.subcommand == "requests":
        if args.req_action == "run":
            cmd_requests_run(args)
        else:
            p_req.print_help()
    elif args.subcommand == "tests":
        if args.tests_action == "run":
            cmd_tests_run(args)
        else:
            p_tests.print_help()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
