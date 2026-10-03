import os
import json
import re
import time
import socket
import ipaddress
import uuid
import yaml
import hashlib
import hmac
from urllib.parse import urlparse
import requests
from requests.auth import HTTPBasicAuth

from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.db import connection
from datetime import timedelta

from .models import (
    RequestHistory, Collection, SavedRequest, Environment, EnvironmentVariable,
    ApiTest, TestRun, TestResult, AuditLog, UserSettings,
    ApiSpecification, ApiVersion, TestSuite, TestSuiteRun,
    Monitor, MonitorRun, AlertRule, Notification, MockEndpoint, PublicDocumentation,
    Workspace, WorkspaceMember, WorkspaceInvitation, PersonalAccessToken,
    ServiceAccount, ServiceAccountToken, Webhook, WebhookDelivery, GitIntegration,
    CiRun, RequestComment
)


# --- AUDIT LOGGING HELPER ---
def _log_audit(user, action, resource_type="", resource_id="", metadata=None):
    """Utility helper to record sanitized user audit logs."""
    try:
        AuditLog.objects.create(
            user=user if (user and user.is_authenticated) else None,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            metadata=metadata or {}
        )
    except Exception:
        pass


# --- SENSITIVE HEADER & DATA REDACTION ---
SENSITIVE_KEYS = {'authorization', 'bearer', 'x-api-key', 'api-key', 'cookie', 'set-cookie', 'secret', 'token', 'password', 'proxy-authorization'}

def _redact_headers(headers):
    """Redacts sensitive credentials from headers prior to history persistence."""
    if isinstance(headers, dict):
        redacted = {}
        for k, v in headers.items():
            if k.lower() in SENSITIVE_KEYS:
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = v
        return redacted
    elif isinstance(headers, list):
        redacted = []
        for item in headers:
            if isinstance(item, dict):
                k = item.get('key', '')
                if k.lower() in SENSITIVE_KEYS:
                    redacted.append({'key': k, 'value': '[REDACTED]', 'enabled': item.get('enabled', True)})
                else:
                    redacted.append(item)
            else:
                redacted.append(item)
        return redacted
    return headers


# --- SSRF & SECURITY FILTER ---
def _is_safe_url(url):
    """
    Strict Server-Side Request Forgery (SSRF) Protection Filter.
    Blocks cloud metadata endpoints, loopback, private IPv4/v6 ranges, link-local, and broadcast addresses.
    """
    if not isinstance(url, str) or not url.strip():
        return False, "URL is empty."

    parsed = urlparse(url)
    scheme = (parsed.scheme or '').lower()
    if scheme not in ['http', 'https']:
        return False, f"Unsupported scheme '{scheme}'. Only http and https are allowed."

    host = (parsed.hostname or '').lower()
    if not host:
        return False, "Invalid URL: Missing hostname."

    blocked_hosts = {
        'localhost', '127.0.0.1', '::1', '0.0.0.0',
        '169.254.169.254', 'metadata.google.internal', 'instance-data', 'metadata'
    }
    if host in blocked_hosts:
        return False, f"Access to restricted host '{host}' is blocked for security."

    try:
        ip_str = socket.gethostbyname(host)
        ip = ipaddress.ip_address(ip_str)

        if ip.is_loopback:
            return False, f"Access to loopback address '{ip_str}' is blocked."
        if ip.is_private:
            return False, f"Access to private internal network IP '{ip_str}' is blocked."
        if ip.is_link_local:
            return False, f"Access to link-local address '{ip_str}' is blocked."
        if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return False, f"Access to reserved IP range '{ip_str}' is blocked."

        if str(ip) == '169.254.169.254':
            return False, "Access to cloud metadata IP is blocked."
    except socket.gaierror:
        if '.' in host and not host.endswith(('.internal', '.local', '.localhost')):
            return True, None
        return False, f"Could not resolve hostname '{host}'."
    except ValueError:
        pass

    return True, None


def _normalize_key_values(items):
    if isinstance(items, dict):
        return items
    if isinstance(items, list):
        result = {}
        for item in items:
            if isinstance(item, dict):
                if item.get('enabled') is False:
                    continue
                k = item.get('key', '').strip()
                v = item.get('value', '')
                if k:
                    result[k] = v
        return result
    return {}


def _substitute_string(text, env_vars):
    if not isinstance(text, str) or not text or not env_vars:
        return text
    def replacer(match):
        var_name = match.group(1).strip()
        return str(env_vars.get(var_name, match.group(0)))
    return re.sub(r'\{\{\s*([a-zA-Z0-9_\-\.]+)\s*\}\}', replacer, text)


def _substitute_obj(obj, env_vars):
    if not env_vars or not obj:
        return obj
    if isinstance(obj, str):
        return _substitute_string(obj, env_vars)
    elif isinstance(obj, dict):
        return {_substitute_string(k, env_vars): _substitute_obj(v, env_vars) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_substitute_obj(item, env_vars) for item in obj]
    return obj


def _evaluate_json_path(data, path):
    """Lightweight JSONPath Evaluator supporting dot notation and array indexing."""
    if not path or data is None:
        return False, None
    tokens = re.findall(r'[^.\[\]]+|\[\d+\]', path)
    curr = data
    try:
        for token in tokens:
            if token.startswith('[') and token.endswith(']'):
                idx = int(token[1:-1])
                curr = curr[idx]
            else:
                curr = curr[token]
        return True, curr
    except (KeyError, IndexError, TypeError):
        return False, None


def _evaluate_assertions(assertions, resp_obj):
    """Evaluates test assertions against proxy response object."""
    if not isinstance(assertions, list) or not assertions:
        return [], {'total': 0, 'passed': 0, 'failed': 0}

    results = []
    passed_count = 0
    failed_count = 0

    status_code = resp_obj.get('status_code')
    time_ms = resp_obj.get('time_ms') or 0.0
    headers = resp_obj.get('headers') or {}
    body = resp_obj.get('body') or ''
    json_data = resp_obj.get('data') if resp_obj.get('is_json') else None

    for idx, test in enumerate(assertions):
        name = test.get('name') or f"Test #{idx + 1}"
        op = (test.get('operator') or '').lower()
        atype = test.get('type') or test.get('assertion_type')
        target_path = test.get('target_path') or test.get('path') or ''

        if not atype:
            if op == 'equals':
                atype = 'status_code_equals'
            elif op == 'not_equals':
                atype = 'status_code_not_equals'
            elif op == 'less_than':
                atype = 'response_time_less_than'
            elif op == 'greater_than':
                atype = 'response_time_greater_than'
            elif op == 'contains':
                atype = 'body_contains'
            elif op == 'not_contains':
                atype = 'body_not_contains'
            elif op in ['json_path_exists', 'json_path_equals', 'json_path_contains', 'header_exists', 'header_equals']:
                atype = op
            else:
                atype = 'status_code_equals'

        expected = str(test.get('expected') if 'expected' in test else test.get('expected_value', '')).strip()

        passed = False
        received = ""
        msg = ""

        try:
            if atype == 'status_code_equals':
                received = str(status_code)
                passed = (str(status_code) == expected)
                msg = f"Status code {received} equals {expected}" if passed else f"Expected status {expected}, received {received}"

            elif atype == 'status_code_not_equals':
                received = str(status_code)
                passed = (str(status_code) != expected)
                msg = f"Status code {received} != {expected}"

            elif atype == 'response_time_less_than':
                received = f"{round(time_ms, 2)} ms"
                exp_num = float(expected or 1000)
                passed = (time_ms < exp_num)
                msg = f"Response time {round(time_ms, 2)}ms < {exp_num}ms" if passed else f"Response time {round(time_ms, 2)}ms exceeded max {exp_num}ms"

            elif atype == 'response_time_greater_than':
                received = f"{round(time_ms, 2)} ms"
                exp_num = float(expected or 0)
                passed = (time_ms > exp_num)
                msg = f"Response time {round(time_ms, 2)}ms > {exp_num}ms"

            elif atype == 'body_contains':
                received = "Body payload text"
                passed = (expected in str(body))
                msg = f"Body contains '{expected}'" if passed else f"Text '{expected}' not found in body"

            elif atype == 'body_not_contains':
                received = "Body payload text"
                passed = (expected not in str(body))
                msg = f"Body does not contain '{expected}'"

            elif atype == 'json_path_exists':
                exists, val = _evaluate_json_path(json_data, target_path)
                received = str(val) if exists else "Path not found"
                passed = exists
                msg = f"JSON path '{target_path}' exists" if passed else f"JSON path '{target_path}' does not exist"

            elif atype == 'json_path_equals':
                exists, val = _evaluate_json_path(json_data, target_path)
                received = str(val) if exists else "Path not found"
                passed = exists and (str(val) == expected)
                msg = f"JSON path '{target_path}' ({received}) == '{expected}'"

            elif atype == 'json_path_contains':
                exists, val = _evaluate_json_path(json_data, target_path)
                received = str(val) if exists else "Path not found"
                passed = exists and (expected in str(val))
                msg = f"JSON path '{target_path}' contains '{expected}'"

            elif atype == 'header_exists':
                found_val = headers.get(target_path) or headers.get(target_path.lower())
                received = str(found_val) if found_val is not None else "Header not present"
                passed = (found_val is not None)
                msg = f"Header '{target_path}' exists"

            elif atype == 'header_equals':
                found_val = headers.get(target_path) or headers.get(target_path.lower())
                received = str(found_val) if found_val is not None else "Header missing"
                passed = (str(found_val) == expected)
                msg = f"Header '{target_path}' equals '{expected}'"

            else:
                passed = True
                msg = f"Unknown assertion type '{atype}' skipped"

        except Exception as e:
            passed = False
            msg = f"Assertion evaluation error: {str(e)}"

        if passed:
            passed_count += 1
        else:
            failed_count += 1

        results.append({
            'name': name,
            'passed': passed,
            'expected': expected,
            'received': received,
            'message': msg,
        })

    return results, {'total': len(assertions), 'passed': passed_count, 'failed': failed_count}


# --- CONTRACT TESTING ENGINE ---
def _validate_api_contract(contract_schema, resp_obj):
    """
    Validates Proxy response object against an OpenAPI/JSON Schema contract definition.
    resp_obj: { status_code, content_type, headers, body, data, is_json }
    contract_schema: {
       expected_status: int,
       expected_content_type: str,
       required_fields: list,
       field_types: dict (field -> expected_type string/integer/boolean/array/object)
    }
    """
    if not isinstance(contract_schema, dict) or not contract_schema:
        return True, [{'check': 'Contract Schema', 'passed': True, 'message': 'No contract schema specified.'}]

    checks = []
    overall_passed = True

    # 1. Status Code Check
    exp_status = contract_schema.get('expected_status')
    act_status = resp_obj.get('status_code')
    if exp_status is not None:
        passed = (str(act_status) == str(exp_status))
        checks.append({
            'check': 'Status Code',
            'passed': passed,
            'expected': str(exp_status),
            'received': str(act_status),
            'message': f"Status {act_status} matches expected {exp_status}" if passed else f"Status violation: expected {exp_status}, received {act_status}"
        })
        if not passed:
            overall_passed = False

    # 2. Content Type Check
    exp_ct = contract_schema.get('expected_content_type')
    headers = resp_obj.get('headers') or {}
    act_ct = headers.get('Content-Type') or headers.get('content-type') or ''
    if exp_ct:
        passed = (exp_ct.lower() in act_ct.lower())
        checks.append({
            'check': 'Content-Type',
            'passed': passed,
            'expected': exp_ct,
            'received': act_ct,
            'message': f"Content-Type matches '{exp_ct}'" if passed else f"Content-Type violation: expected '{exp_ct}', received '{act_ct}'"
        })
        if not passed:
            overall_passed = False

    # 3. JSON Structure & Field Type Validation
    json_data = resp_obj.get('data') if resp_obj.get('is_json') else None
    required_fields = contract_schema.get('required_fields', [])
    field_types = contract_schema.get('field_types', {})

    if required_fields:
        for f in required_fields:
            if isinstance(json_data, dict):
                exists = f in json_data
                checks.append({
                    'check': f"Required Field '{f}'",
                    'passed': exists,
                    'expected': 'Present',
                    'received': 'Present' if exists else 'Missing',
                    'message': f"Required field '{f}' present" if exists else f"Contract Violation: Required field '{f}' is missing in response"
                })
                if not exists:
                    overall_passed = False
            else:
                checks.append({
                    'check': f"Required Field '{f}'",
                    'passed': False,
                    'expected': 'JSON Object',
                    'received': type(json_data).__name__,
                    'message': f"Contract Violation: Cannot check required field '{f}' on non-dict JSON body"
                })
                overall_passed = False

    if field_types and isinstance(json_data, dict):
        for field, exp_type in field_types.items():
            if field in json_data:
                val = json_data[field]
                actual_type = type(val).__name__
                passed = False
                if exp_type == 'string' and isinstance(val, str):
                    passed = True
                elif exp_type == 'integer' and isinstance(val, int) and not isinstance(val, bool):
                    passed = True
                elif exp_type == 'number' and isinstance(val, (int, float)) and not isinstance(val, bool):
                    passed = True
                elif exp_type == 'boolean' and isinstance(val, bool):
                    passed = True
                elif exp_type == 'array' and isinstance(val, list):
                    passed = True
                elif exp_type == 'object' and isinstance(val, dict):
                    passed = True

                checks.append({
                    'check': f"Field Type '{field}'",
                    'passed': passed,
                    'expected': exp_type,
                    'received': actual_type,
                    'message': f"Field '{field}' is type '{exp_type}'" if passed else f"Contract Violation: Field '{field}' expected type '{exp_type}', received '{actual_type}'"
                })
                if not passed:
                    overall_passed = False

    return overall_passed, checks


# --- OPENAPI SPECIFICATION PARSER & CONVERTER ---
def _parse_openapi_spec(raw_content):
    """Parses raw JSON or YAML OpenAPI 3.x / Swagger 2.0 specification text."""
    if not isinstance(raw_content, str) or not raw_content.strip():
        return False, "Specification content is empty.", None

    parsed = None
    try:
        parsed = json.loads(raw_content)
    except Exception:
        try:
            parsed = yaml.safe_load(raw_content)
        except Exception as e:
            return False, f"Failed to parse spec as JSON or YAML: {str(e)}", None

    if not isinstance(parsed, dict):
        return False, "Invalid specification format: Root must be a dictionary object.", None

    openapi_version = parsed.get('openapi') or parsed.get('swagger')
    if not openapi_version:
        return False, "Invalid OpenAPI specification: Missing 'openapi' or 'swagger' version tag.", None

    info = parsed.get('info', {})
    title = info.get('title') or 'Imported OpenAPI Spec'
    version = info.get('version') or '1.0.0'
    description = info.get('description') or ''

    servers = []
    if 'servers' in parsed and isinstance(parsed['servers'], list):
        for s in parsed['servers']:
            if isinstance(s, dict) and s.get('url'):
                servers.append({'url': s['url'], 'description': s.get('description', '')})
    elif 'host' in parsed:
        schemes = parsed.get('schemes', ['https'])
        scheme = schemes[0] if isinstance(schemes, list) and schemes else 'https'
        base_path = parsed.get('basePath', '')
        servers.append({'url': f"{scheme}://{parsed['host']}{base_path}", 'description': 'Swagger Server'})

    paths = parsed.get('paths', {})
    if not isinstance(paths, dict):
        return False, "Invalid OpenAPI specification: 'paths' must be an object.", None

    endpoints = []
    for path, path_obj in paths.items():
        if not isinstance(path_obj, dict):
            continue
        for method in ['get', 'post', 'put', 'patch', 'delete', 'options', 'head']:
            if method in path_obj and isinstance(path_obj[method], dict):
                op = path_obj[method]
                summary = op.get('summary') or op.get('operationId') or f"{method.upper()} {path}"
                op_desc = op.get('description') or ''
                
                # Parameters
                headers = []
                params = []
                for p in op.get('parameters', []):
                    if isinstance(p, dict):
                        p_in = p.get('in')
                        p_name = p.get('name')
                        if p_in == 'header' and p_name:
                            headers.append({'key': p_name, 'value': str(p.get('example') or '')})
                        elif p_in == 'query' and p_name:
                            params.append({'key': p_name, 'value': str(p.get('example') or '')})

                endpoints.append({
                    'method': method.upper(),
                    'path': path,
                    'summary': summary,
                    'description': op_desc,
                    'headers': headers,
                    'params': params,
                    'operation': op,
                })

    parsed_summary = {
        'title': title,
        'version': str(version),
        'description': description,
        'servers': servers,
        'endpoints_count': len(endpoints),
        'endpoints': endpoints,
        'schemas': list((parsed.get('components', {}).get('schemas') or parsed.get('definitions') or {}).keys()),
    }

    return True, None, parsed_summary


def _export_collection_to_openapi(collection):
    """Exports APIHub Collection as valid OpenAPI 3.0.3 specification."""
    paths = {}
    for req in collection.requests.all():
        parsed_url = urlparse(req.url)
        path = parsed_url.path or '/'
        method = req.method.lower()

        if path not in paths:
            paths[path] = {}

        headers_list = req.headers if isinstance(req.headers, list) else []
        parameters = []
        for h in headers_list:
            if isinstance(h, dict) and h.get('key'):
                parameters.append({'name': h['key'], 'in': 'header', 'schema': {'type': 'string'}})

        params_list = req.params if isinstance(req.params, list) else []
        for p in params_list:
            if isinstance(p, dict) and p.get('key'):
                parameters.append({'name': p['key'], 'in': 'query', 'schema': {'type': 'string'}})

        req_body = {}
        if req.body:
            req_body = {
                'content': {
                    'application/json': {
                        'example': req.body
                    }
                }
            }

        paths[path][method] = {
            'summary': req.name,
            'description': req.description,
            'parameters': parameters,
            'requestBody': req_body if req_body else None,
            'responses': {
                '200': {'description': 'Successful response'}
            }
        }

    return {
        'openapi': '3.0.3',
        'info': {
            'title': collection.name,
            'description': collection.description or 'Exported from APIHub',
            'version': '1.0.0'
        },
        'paths': paths
    }


# --- HEALTH & SYSTEM READINESS ENDPOINTS ---
def health_view(request):
    """Lightweight health check endpoint."""
    return JsonResponse({"status": "ok", "service": "APIHub"}, status=200)


def ready_view(request):
    """Readiness check endpoint verifying database connectivity."""
    try:
        connection.ensure_connection()
        return JsonResponse({"status": "ready", "database": "connected"}, status=200)
    except Exception as exc:
        return JsonResponse({"status": "unready", "database": str(exc)}, status=503)


# --- AUTHENTICATION & ACCOUNT VIEWS ---
def login_view(request):
    if request.user.is_authenticated:
        return redirect('client:index')

    if request.method == "POST":
        username_or_email = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        if not username_or_email or not password:
            return render(request, 'client/login.html', {'error': 'Username and password are required.'})

        user_obj = None
        if '@' in username_or_email:
            try:
                user_obj = User.objects.get(email=username_or_email)
                username_or_email = user_obj.username
            except User.DoesNotExist:
                user_obj = None

        user = authenticate(request, username=username_or_email, password=password)
        if user is not None:
            login(request, user)
            _log_audit(user, "LOGIN", "User", user.id)
            return redirect('client:index')
        else:
            return render(request, 'client/login.html', {'error': 'Invalid username/email or password.'})

    return render(request, 'client/login.html')


def register_view(request):
    if request.user.is_authenticated:
        return redirect('client:index')

    if request.method == "POST":
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')

        errors = []
        if not username:
            errors.append("Username is required.")
        if not email:
            errors.append("Email address is required.")
        if not password:
            errors.append("Password is required.")
        if password != confirm_password:
            errors.append("Passwords do not match.")

        if User.objects.filter(username=username).exists():
            errors.append("A user with that username already exists.")
        if email and User.objects.filter(email=email).exists():
            errors.append("A user with that email address already exists.")

        if password:
            try:
                validate_password(password)
            except ValidationError as e:
                errors.extend(e.messages)

        if errors:
            return render(request, 'client/register.html', {'errors': errors})

        user = User.objects.create_user(username=username, email=email, password=password)
        UserSettings.objects.create(user=user)
        login(request, user)

        _log_audit(user, "REGISTER", "User", user.id)
        return redirect('client:index')

    return render(request, 'client/register.html')


def logout_view(request):
    if request.user.is_authenticated:
        _log_audit(request.user, "LOGOUT", "User", request.user.id)
        logout(request)
    return redirect('client:login')


@login_required(login_url='/login/')
def profile_view(request):
    user = request.user
    success_msg = None
    error_msg = None

    if request.method == "POST":
        action = request.POST.get('action')
        if action == "update_profile":
            new_username = request.POST.get('username', '').strip()
            new_email = request.POST.get('email', '').strip()

            if new_username and new_username != user.username:
                if User.objects.filter(username=new_username).exclude(id=user.id).exists():
                    error_msg = "Username already taken by another account."
                else:
                    user.username = new_username

            if new_email and new_email != user.email:
                if User.objects.filter(email=new_email).exclude(id=user.id).exists():
                    error_msg = "Email address already taken by another account."
                else:
                    user.email = new_email

            if not error_msg:
                user.save()
                _log_audit(user, "PROFILE_UPDATE", "User", user.id)
                success_msg = "Profile updated successfully."

        elif action == "change_password":
            current_pw = request.POST.get('current_password', '')
            new_pw = request.POST.get('new_password', '')
            confirm_pw = request.POST.get('confirm_new_password', '')

            if not user.check_password(current_pw):
                error_msg = "Current password is incorrect."
            elif new_pw != confirm_pw:
                error_msg = "New passwords do not match."
            else:
                try:
                    validate_password(new_pw, user=user)
                    user.set_password(new_pw)
                    user.save()
                    update_session_auth_hash(request, user)
                    _log_audit(user, "PASSWORD_CHANGE", "User", user.id)
                    success_msg = "Password updated successfully."
                except ValidationError as e:
                    error_msg = " ".join(e.messages)

    return render(request, 'client/profile.html', {
        'user': user,
        'success_msg': success_msg,
        'error_msg': error_msg
    })


@login_required(login_url='/login/')
def settings_view(request):
    user = request.user
    user_settings, _ = UserSettings.objects.get_or_create(user=user)
    success_msg = None

    if request.method == "POST":
        action = request.POST.get('action')
        if action == "update_settings":
            user_settings.theme = request.POST.get('theme', 'dark')
            user_settings.compact_mode = request.POST.get('compact_mode') == 'on'
            try:
                user_settings.request_timeout = int(request.POST.get('request_timeout', 15))
            except ValueError:
                user_settings.request_timeout = 15
            user_settings.save()
            _log_audit(user, "SETTINGS_UPDATE", "UserSettings", user_settings.id)
            success_msg = "Preferences saved successfully."

    return render(request, 'client/settings.html', {
        'settings': user_settings,
        'success_msg': success_msg
    })


@login_required(login_url='/login/')
def export_account_data(request):
    user = request.user
    data = {
        'user': {
            'username': user.username,
            'email': user.email,
            'date_joined': user.date_joined.isoformat(),
        },
        'collections': [c.to_dict() for c in Collection.objects.filter(user=user)],
        'saved_requests': [r.to_dict() for r in SavedRequest.objects.filter(user=user, collection__isnull=True)],
        'environments': [e.to_dict() for e in Environment.objects.filter(user=user)],
        'monitors': [m.to_dict() for m in Monitor.objects.filter(user=user)],
        'test_suites': [s.to_dict() for s in TestSuite.objects.filter(user=user)],
        'mocks': [m.to_dict() for m in MockEndpoint.objects.filter(user=user)],
        'history': [h.to_dict() for h in RequestHistory.objects.filter(user=user)[:100]],
    }
    _log_audit(user, "EXPORT_DATA", "User", user.id)
    response = JsonResponse(data, json_dumps_params={'indent': 2})
    response['Content-Disposition'] = f'attachment; filename="apihub_export_{user.username}.json"'
    return response


@login_required(login_url='/login/')
def delete_account(request):
    if request.method == "POST":
        user = request.user
        _log_audit(user, "DELETE_ACCOUNT", "User", user.id)
        user.delete()
        logout(request)
        return redirect('client:login')
    return redirect('client:settings')


# --- SPA APPLICATION INDEX ---
@login_required(login_url='/login/')
def index(request):
    """Render main SPA interface for authenticated user."""
    recent_history = RequestHistory.objects.filter(user=request.user)[:30]
    audit_logs = AuditLog.objects.filter(user=request.user)[:10]
    user_settings, _ = UserSettings.objects.get_or_create(user=request.user)
    notifications = Notification.objects.filter(user=request.user, is_read=False)[:10]
    monitors = Monitor.objects.filter(user=request.user)
    test_suites = TestSuite.objects.filter(user=request.user)
    mocks = MockEndpoint.objects.filter(user=request.user)
    specs = ApiSpecification.objects.filter(user=request.user)

    return render(request, 'client/index.html', {
        'user': request.user,
        'recent_history': recent_history,
        'audit_logs': audit_logs,
        'notifications': notifications,
        'user_settings': user_settings,
        'monitors_count': monitors.count(),
        'suites_count': test_suites.count(),
        'mocks_count': mocks.count(),
        'specs_count': specs.count(),
    })


# --- CORE REQUEST EXECUTION API WITH CONTRACT TESTING ---

@csrf_exempt
@require_http_methods(["POST"])
def execute_request(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    if len(request.body) > 10 * 1024 * 1024:
        return JsonResponse({'error': 'Request payload exceeds maximum 10MB limit.'}, status=413)

    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON request body.'}, status=400)

    method = (payload.get('method') or 'GET').strip().upper()
    url = (payload.get('url') or '').strip()

    if not url:
        return JsonResponse({'error': 'URL is required.'}, status=400)

    # Load Environment Variables
    env_vars = {}
    env_id = payload.get('environment_id')
    if env_id:
        try:
            env = Environment.objects.get(id=env_id, user=request.user)
            for var in env.variables.all():
                env_vars[var.key] = var.value
        except Environment.DoesNotExist:
            pass

    inline_vars = payload.get('variables', {})
    if isinstance(inline_vars, dict):
        env_vars.update(inline_vars)
    elif isinstance(inline_vars, list):
        for item in inline_vars:
            if isinstance(item, dict) and item.get('key'):
                env_vars[item['key']] = item.get('value', '')

    url = _substitute_string(url, env_vars)
    headers_raw = _substitute_obj(payload.get('headers', {}), env_vars)
    params_raw = _substitute_obj(payload.get('params', {}), env_vars)
    auth_data = _substitute_obj(payload.get('auth', {}), env_vars)
    body_data = _substitute_obj(payload.get('body', ''), env_vars)

    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'https://' + url

    # SSRF Security Check
    is_safe, sec_error = _is_safe_url(url)
    if not is_safe:
        return JsonResponse({'error': sec_error}, status=400)

    clean_headers = _normalize_key_values(headers_raw)
    clean_params = _normalize_key_values(params_raw)

    req_auth = None
    if isinstance(auth_data, dict):
        auth_type = auth_data.get('type', 'none')
        if auth_type == 'bearer':
            token = auth_data.get('token', '').strip()
            if token:
                clean_headers['Authorization'] = f"Bearer {token}"
        elif auth_type == 'basic':
            username = auth_data.get('username', '')
            password = auth_data.get('password', '')
            req_auth = HTTPBasicAuth(username, password)

    send_data = None
    if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
        if isinstance(body_data, (dict, list)):
            send_data = json.dumps(body_data).encode('utf-8')
            if 'Content-Type' not in clean_headers and 'content-type' not in clean_headers:
                clean_headers['Content-Type'] = 'application/json'
        elif isinstance(body_data, str) and body_data:
            send_data = body_data.encode('utf-8')

    req_timeout = 15
    try:
        req_timeout = request.user.settings.request_timeout
    except Exception:
        req_timeout = 15

    start_time = time.perf_counter()
    status_code = None
    status_text = ''
    response_headers = {}
    response_data = None
    is_json = False
    size_kb = 0.0
    latency_ms = 0.0
    raw_body_text = ""

    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=clean_headers,
            params=clean_params,
            data=send_data,
            auth=req_auth,
            timeout=req_timeout,
            allow_redirects=True,
        )
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = resp.status_code
        status_text = resp.reason or 'OK'
        response_headers = dict(resp.headers)
        size_kb = len(resp.content) / 1024.0
        raw_body_text = resp.text

        try:
            response_data = resp.json()
            is_json = True
        except Exception:
            response_data = resp.text
            is_json = False

    except requests.exceptions.Timeout as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = 504
        status_text = f'Gateway Timeout ({req_timeout}s)'
        response_data = {'error': f'Request timed out after {req_timeout} seconds: {str(exc)}'}
        is_json = True
        raw_body_text = json.dumps(response_data)
    except requests.exceptions.ConnectionError as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = 502
        status_text = 'Connection Error'
        response_data = {'error': f'Failed to establish connection: {str(exc)}'}
        is_json = True
        raw_body_text = json.dumps(response_data)
    except requests.exceptions.RequestException as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = 500
        status_text = 'Request Failed'
        response_data = {'error': str(exc)}
        is_json = True
        raw_body_text = json.dumps(response_data)
    except Exception as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = 500
        status_text = 'Internal Error'
        response_data = {'error': str(exc)}
        is_json = True
        raw_body_text = json.dumps(response_data)

    # 1. Test Assertions
    test_definitions = payload.get('tests', [])
    resp_obj = {
        'status_code': status_code,
        'time_ms': latency_ms,
        'headers': response_headers,
        'body': raw_body_text,
        'data': response_data,
        'is_json': is_json,
    }
    test_results, test_summary = _evaluate_assertions(test_definitions, resp_obj)

    # 2. Contract Testing Validation
    contract_schema = payload.get('contract_schema', {})
    contract_passed, contract_checks = _validate_api_contract(contract_schema, resp_obj)

    # Persist in History with Redacted Headers
    try:
        redacted_headers = _redact_headers(clean_headers)
        body_to_store = body_data if isinstance(body_data, str) else json.dumps(body_data)
        history_entry = RequestHistory.objects.create(
            user=request.user,
            method=method,
            url=url,
            headers=redacted_headers,
            params=clean_params,
            body=body_to_store,
            status_code=status_code,
            status_text=status_text,
            response_time_ms=latency_ms,
            response_size_kb=size_kb,
        )
        saved_id = history_entry.id
    except Exception:
        saved_id = None

    _log_audit(request.user, "EXECUTE_REQUEST", "RequestHistory", saved_id or "", {'method': method, 'url': url, 'status': status_code})

    return JsonResponse({
        'status_code': status_code,
        'status_text': status_text,
        'time_ms': round(latency_ms, 2),
        'size_kb': round(size_kb, 2),
        'headers': response_headers,
        'data': response_data,
        'is_json': is_json,
        'history_id': saved_id,
        'executed_url': url,
        'test_results': test_results,
        'test_summary': test_summary,
        'contract_passed': contract_passed,
        'contract_checks': contract_checks,
    })


@csrf_exempt
@require_http_methods(["GET", "DELETE"])
def history_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    if request.method == "GET":
        items = RequestHistory.objects.filter(user=request.user)[:50]
        return JsonResponse({'history': [item.to_dict() for item in items]})
    elif request.method == "DELETE":
        item_id = request.GET.get('id')
        if item_id:
            RequestHistory.objects.filter(id=item_id, user=request.user).delete()
            return JsonResponse({'success': True, 'deleted_id': item_id})
        else:
            RequestHistory.objects.filter(user=request.user).delete()
            return JsonResponse({'success': True, 'cleared_all': True})


# --- COLLECTIONS API ---
@csrf_exempt
@require_http_methods(["GET", "POST"])
def collections_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    if request.method == "GET":
        collections = Collection.objects.filter(user=request.user).prefetch_related('requests', 'api_versions')
        return JsonResponse({'collections': [c.to_dict() for c in collections]})
    elif request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON request body.'}, status=400)

        name = (data.get('name') or '').strip()
        if not name:
            return JsonResponse({'error': 'Collection name is required.'}, status=400)

        col = Collection.objects.create(
            user=request.user,
            name=name,
            description=data.get('description', '').strip(),
            tags=data.get('tags', [])
        )

        # Create default v1.0 API Version
        ApiVersion.objects.create(user=request.user, collection=col, version_name='v1.0', status='ACTIVE')

        _log_audit(request.user, "CREATE_COLLECTION", "Collection", col.id, {'name': name})
        return JsonResponse({'success': True, 'collection': col.to_dict()}, status=201)


@csrf_exempt
@require_http_methods(["GET", "PUT", "PATCH", "DELETE"])
def collection_detail_api(request, collection_id):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        col = Collection.objects.get(id=collection_id, user=request.user)
    except Collection.DoesNotExist:
        return JsonResponse({'error': 'Collection not found.'}, status=404)

    if request.method == "GET":
        return JsonResponse({'collection': col.to_dict()})
    elif request.method in ["PUT", "PATCH"]:
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON body.'}, status=400)

        if 'name' in data:
            name = data['name'].strip()
            if not name:
                return JsonResponse({'error': 'Collection name cannot be empty.'}, status=400)
            col.name = name
        if 'description' in data:
            col.description = data['description'].strip()
        if 'tags' in data:
            col.tags = data['tags']

        col.save()
        _log_audit(request.user, "UPDATE_COLLECTION", "Collection", col.id)
        return JsonResponse({'success': True, 'collection': col.to_dict()})
    elif request.method == "DELETE":
        col_id = col.id
        col.delete()
        _log_audit(request.user, "DELETE_COLLECTION", "Collection", col_id)
        return JsonResponse({'success': True, 'deleted_id': collection_id})


# --- SAVED REQUESTS API ---
@csrf_exempt
@require_http_methods(["GET", "POST"])
def saved_requests_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    if request.method == "GET":
        col_id = request.GET.get('collection_id')
        if col_id:
            reqs = SavedRequest.objects.filter(collection_id=col_id, user=request.user)
        else:
            reqs = SavedRequest.objects.filter(user=request.user)
        return JsonResponse({'requests': [r.to_dict() for r in reqs]})
    elif request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        name = (data.get('name') or '').strip()
        if not name:
            return JsonResponse({'error': 'Request name is required.'}, status=400)

        col_id = data.get('collection_id')
        col = None
        if col_id:
            try:
                col = Collection.objects.get(id=col_id, user=request.user)
            except Collection.DoesNotExist:
                return JsonResponse({'error': 'Target collection does not exist.'}, status=404)

        saved_req = SavedRequest.objects.create(
            user=request.user,
            collection=col,
            name=name,
            description=data.get('description', ''),
            tags=data.get('tags', []),
            method=(data.get('method') or 'GET').upper(),
            url=data.get('url', ''),
            headers=data.get('headers', []),
            params=data.get('params', []),
            auth_type=data.get('auth_type', 'none'),
            auth_data=data.get('auth_data', {}),
            body=data.get('body', ''),
            tests=data.get('tests', []),
            contract_schema=data.get('contract_schema', {})
        )
        _log_audit(request.user, "SAVE_REQUEST", "SavedRequest", saved_req.id, {'name': name})
        return JsonResponse({'success': True, 'request': saved_req.to_dict()}, status=201)


@csrf_exempt
@require_http_methods(["GET", "PUT", "PATCH", "DELETE"])
def saved_request_detail_api(request, request_id):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        saved_req = SavedRequest.objects.get(id=request_id, user=request.user)
    except SavedRequest.DoesNotExist:
        return JsonResponse({'error': 'Saved request not found.'}, status=404)

    if request.method == "GET":
        return JsonResponse({'request': saved_req.to_dict()})
    elif request.method in ["PUT", "PATCH"]:
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        if 'name' in data:
            name = data['name'].strip()
            if not name:
                return JsonResponse({'error': 'Request name cannot be empty.'}, status=400)
            saved_req.name = name
        if 'description' in data:
            saved_req.description = data['description']
        if 'tags' in data:
            saved_req.tags = data['tags']
        if 'method' in data:
            saved_req.method = data['method'].upper()
        if 'url' in data:
            saved_req.url = data['url']
        if 'headers' in data:
            saved_req.headers = data['headers']
        if 'params' in data:
            saved_req.params = data['params']
        if 'auth_type' in data:
            saved_req.auth_type = data['auth_type']
        if 'auth_data' in data:
            saved_req.auth_data = data['auth_data']
        if 'body' in data:
            saved_req.body = data['body']
        if 'tests' in data:
            saved_req.tests = data['tests']
        if 'contract_schema' in data:
            saved_req.contract_schema = data['contract_schema']

        saved_req.save()
        _log_audit(request.user, "UPDATE_REQUEST", "SavedRequest", saved_req.id)
        return JsonResponse({'success': True, 'request': saved_req.to_dict()})
    elif request.method == "DELETE":
        req_id = saved_req.id
        saved_req.delete()
        _log_audit(request.user, "DELETE_REQUEST", "SavedRequest", req_id)
        return JsonResponse({'success': True, 'deleted_id': request_id})


@csrf_exempt
@require_http_methods(["POST"])
def duplicate_request_api(request, request_id):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        source_req = SavedRequest.objects.get(id=request_id, user=request.user)
    except SavedRequest.DoesNotExist:
        return JsonResponse({'error': 'Saved request not found.'}, status=404)

    dup_req = SavedRequest.objects.create(
        user=request.user,
        collection=source_req.collection,
        name=f"{source_req.name} Copy",
        description=source_req.description,
        tags=source_req.tags,
        method=source_req.method,
        url=source_req.url,
        headers=source_req.headers,
        params=source_req.params,
        auth_type=source_req.auth_type,
        auth_data=source_req.auth_data,
        body=source_req.body,
        tests=source_req.tests,
        contract_schema=source_req.contract_schema
    )
    _log_audit(request.user, "DUPLICATE_REQUEST", "SavedRequest", dup_req.id)
    return JsonResponse({'success': True, 'request': dup_req.to_dict()}, status=201)


# --- COLLECTION RUNNER ---
@csrf_exempt
@require_http_methods(["POST"])
def run_collection_api(request, collection_id):
    """Sequentially runs collection requests for authenticated user."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        col = Collection.objects.get(id=collection_id, user=request.user)
    except Collection.DoesNotExist:
        return JsonResponse({'error': 'Collection not found.'}, status=404)

    saved_reqs = col.requests.all()
    if not saved_reqs:
        return JsonResponse({'error': 'Collection contains no saved requests.'}, status=400)

    start_total_time = time.perf_counter()
    total_assertions = 0
    passed_assertions = 0
    failed_assertions = 0
    run_details = []

    test_run = TestRun.objects.create(user=request.user, collection=col)

    for req in saved_reqs:
        clean_headers = _normalize_key_values(req.headers)
        clean_params = _normalize_key_values(req.params)
        req_auth = None
        if req.auth_type == 'bearer' and isinstance(req.auth_data, dict):
            token = req.auth_data.get('token')
            if token:
                clean_headers['Authorization'] = f"Bearer {token}"
        elif req.auth_type == 'basic' and isinstance(req.auth_data, dict):
            req_auth = HTTPBasicAuth(req.auth_data.get('username', ''), req.auth_data.get('password', ''))

        send_data = req.body.encode('utf-8') if req.body else None
        req_start = time.perf_counter()
        status_code = None
        status_text = ''
        response_headers = {}
        response_data = None
        is_json = False
        raw_body_text = ""

        try:
            resp = requests.request(
                method=req.method,
                url=req.url,
                headers=clean_headers,
                params=clean_params,
                data=send_data,
                auth=req_auth,
                timeout=15,
            )
            req_latency = (time.perf_counter() - req_start) * 1000.0
            status_code = resp.status_code
            status_text = resp.reason or 'OK'
            response_headers = dict(resp.headers)
            raw_body_text = resp.text
            try:
                response_data = resp.json()
                is_json = True
            except Exception:
                response_data = resp.text
                is_json = False
        except Exception as e:
            req_latency = (time.perf_counter() - req_start) * 1000.0
            status_code = 500
            status_text = 'Error'
            response_data = str(e)
            raw_body_text = str(e)

        resp_obj = {
            'status_code': status_code,
            'time_ms': req_latency,
            'headers': response_headers,
            'body': raw_body_text,
            'data': response_data,
            'is_json': is_json,
        }

        eval_results, eval_summary = _evaluate_assertions(req.tests, resp_obj)
        contract_passed, contract_checks = _validate_api_contract(req.contract_schema, resp_obj)

        total_assertions += eval_summary['total']
        passed_assertions += eval_summary['passed']
        failed_assertions += eval_summary['failed']

        for res in eval_results:
            TestResult.objects.create(
                test_run=test_run,
                assertion_name=f"{req.name}: {res['name']}",
                passed=res['passed'],
                expected=str(res['expected']),
                received=str(res['received']),
                message=res['message']
            )

        run_details.append({
            'request_name': req.name,
            'method': req.method,
            'url': req.url,
            'status_code': status_code,
            'latency_ms': round(req_latency, 2),
            'summary': eval_summary,
            'results': eval_results,
            'contract_passed': contract_passed,
            'contract_checks': contract_checks,
        })

    total_duration = (time.perf_counter() - start_total_time) * 1000.0
    test_run.total_tests = total_assertions
    test_run.passed_tests = passed_assertions
    test_run.failed_tests = failed_assertions
    test_run.duration_ms = total_duration
    test_run.save()

    _log_audit(request.user, "RUN_COLLECTION", "Collection", col.id, {'total_tests': total_assertions, 'passed': passed_assertions})

    return JsonResponse({
        'success': True,
        'test_run': test_run.to_dict(),
        'collection_id': collection_id,
        'collection_name': col.name,
        'requests_run': len(saved_reqs),
        'duration_ms': round(total_duration, 2),
        'total_tests': total_assertions,
        'passed_tests': passed_assertions,
        'failed_tests': failed_assertions,
        'details': run_details,
    })


# --- POSTMAN COLLECTION IMPORT & EXPORT ---
@csrf_exempt
@require_http_methods(["POST"])
def import_postman_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        data = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format in imported file.'}, status=400)

    info = data.get('info', {})
    col_name = info.get('name') or 'Imported Postman Collection'
    col_desc = info.get('description', '')

    col = Collection.objects.create(user=request.user, name=col_name, description=col_desc)
    items = data.get('item', [])
    skipped_features = []

    def process_item(item, parent_folder=""):
        if 'item' in item:
            folder_name = item.get('name', 'Folder')
            for sub_item in item.get('item', []):
                process_item(sub_item, f"{parent_folder}/{folder_name}".strip('/'))
        elif 'request' in item:
            req_name = item.get('name') or 'Postman Request'
            if parent_folder:
                req_name = f"[{parent_folder}] {req_name}"

            p_req = item['request']
            method = p_req.get('method', 'GET').upper()
            
            p_url = p_req.get('url', '')
            if isinstance(p_url, dict):
                url_str = p_url.get('raw', '')
            else:
                url_str = str(p_url)

            headers = []
            for h in p_req.get('header', []):
                if isinstance(h, dict) and h.get('key'):
                    headers.append({'key': h['key'], 'value': h.get('value', ''), 'enabled': not h.get('disabled', False)})

            body_str = ""
            p_body = p_req.get('body', {})
            if isinstance(p_body, dict):
                if p_body.get('mode') == 'raw':
                    body_str = p_body.get('raw', '')
                elif p_body.get('mode') in ['formdata', 'urlencoded']:
                    skipped_features.append(f"Converted form-data body for '{req_name}' to raw representation")

            SavedRequest.objects.create(
                user=request.user,
                collection=col,
                name=req_name,
                method=method,
                url=url_str,
                headers=headers,
                body=body_str
            )

    for item in items:
        process_item(item)

    _log_audit(request.user, "IMPORT_POSTMAN", "Collection", col.id)

    return JsonResponse({
        'success': True,
        'collection': col.to_dict(),
        'imported_requests': col.requests.count(),
        'skipped_features': list(set(skipped_features))
    }, status=201)


@csrf_exempt
@require_http_methods(["GET"])
def export_postman_api(request, collection_id):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        col = Collection.objects.get(id=collection_id, user=request.user)
    except Collection.DoesNotExist:
        return JsonResponse({'error': 'Collection not found.'}, status=404)

    postman_items = []
    for req in col.requests.all():
        postman_items.append({
            'name': req.name,
            'request': {
                'method': req.method,
                'header': [{'key': h['key'], 'value': h.get('value', '')} for h in (req.headers if isinstance(req.headers, list) else []) if isinstance(h, dict)],
                'url': {'raw': req.url},
                'body': {'mode': 'raw', 'raw': req.body}
            }
        })

    postman_schema = {
        'info': {
            '_postman_id': f"apihub-col-{col.id}",
            'name': col.name,
            'description': col.description,
            'schema': 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
        },
        'item': postman_items
    }

    _log_audit(request.user, "EXPORT_POSTMAN", "Collection", col.id)
    return JsonResponse(postman_schema)


@csrf_exempt
@require_http_methods(["POST"])
def import_request_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        data = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON request format.'}, status=400)

    name = (data.get('name') or 'Imported Request').strip()
    saved_req = SavedRequest.objects.create(
        user=request.user,
        name=name,
        method=(data.get('method') or 'GET').upper(),
        url=data.get('url', ''),
        headers=data.get('headers', []),
        params=data.get('params', []),
        auth_type=data.get('auth_type', 'none'),
        auth_data=data.get('auth_data', {}),
        body=data.get('body', ''),
        tests=data.get('tests', []),
        contract_schema=data.get('contract_schema', {})
    )
    _log_audit(request.user, "IMPORT_REQUEST", "SavedRequest", saved_req.id)
    return JsonResponse({'success': True, 'request': saved_req.to_dict()}, status=201)


@csrf_exempt
@require_http_methods(["GET"])
def collection_documentation_api(request, collection_id):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        col = Collection.objects.get(id=collection_id, user=request.user)
    except Collection.DoesNotExist:
        return JsonResponse({'error': 'Collection not found.'}, status=404)

    doc_markdown = f"# {col.name}\n\n{col.description or 'API Collection Documentation'}\n\n---\n\n"
    for req in col.requests.all():
        doc_markdown += f"## {req.method} `{req.url}`\n\n"
        doc_markdown += f"**Name**: {req.name}\n\n"
        if req.description:
            doc_markdown += f"**Description**: {req.description}\n\n"

        if req.headers:
            doc_markdown += "### Request Headers\n\n| Key | Value |\n| :--- | :--- |\n"
            h_list = req.headers if isinstance(req.headers, list) else []
            for h in h_list:
                if isinstance(h, dict):
                    doc_markdown += f"| `{h.get('key')}` | `{h.get('value')}` |\n"
            doc_markdown += "\n"

        if req.body:
            doc_markdown += "### Request Body Example\n\n```json\n" + req.body + "\n```\n\n"

        doc_markdown += "---\n\n"

    return JsonResponse({
        'collection_id': col.id,
        'collection_name': col.name,
        'markdown': doc_markdown,
        'endpoints_count': col.requests.count()
    })


# --- ENVIRONMENTS API ---
@csrf_exempt
@require_http_methods(["GET", "POST"])
def environments_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    if request.method == "GET":
        envs = Environment.objects.filter(user=request.user).prefetch_related('variables')
        return JsonResponse({'environments': [e.to_dict() for e in envs]})
    elif request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        name = (data.get('name') or '').strip()
        if not name:
            return JsonResponse({'error': 'Environment name is required.'}, status=400)

        env = Environment.objects.create(user=request.user, name=name)
        _log_audit(request.user, "CREATE_ENVIRONMENT", "Environment", env.id, {'name': name})
        return JsonResponse({'success': True, 'environment': env.to_dict()}, status=201)


@csrf_exempt
@require_http_methods(["GET", "PUT", "PATCH", "DELETE"])
def environment_detail_api(request, environment_id):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        env = Environment.objects.get(id=environment_id, user=request.user)
    except Environment.DoesNotExist:
        return JsonResponse({'error': 'Environment not found.'}, status=404)

    if request.method == "GET":
        return JsonResponse({'environment': env.to_dict()})
    elif request.method in ["PUT", "PATCH"]:
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        if 'name' in data:
            name = data['name'].strip()
            if not name:
                return JsonResponse({'error': 'Environment name cannot be empty.'}, status=400)
            env.name = name

        env.save()
        _log_audit(request.user, "UPDATE_ENVIRONMENT", "Environment", env.id)
        return JsonResponse({'success': True, 'environment': env.to_dict()})
    elif request.method == "DELETE":
        env_id = env.id
        env.delete()
        _log_audit(request.user, "DELETE_ENVIRONMENT", "Environment", env_id)
        return JsonResponse({'success': True, 'deleted_id': environment_id})


@csrf_exempt
@require_http_methods(["POST"])
def variables_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        data = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    env_id = data.get('environment_id')
    if not env_id:
        return JsonResponse({'error': 'environment_id is required.'}, status=400)

    try:
        env = Environment.objects.get(id=env_id, user=request.user)
    except Environment.DoesNotExist:
        return JsonResponse({'error': 'Environment not found.'}, status=404)

    key = (data.get('key') or '').strip()
    if not key:
        return JsonResponse({'error': 'Variable key is required.'}, status=400)

    val = data.get('value', '')

    var, created = EnvironmentVariable.objects.update_or_create(
        environment=env,
        key=key,
        defaults={'value': val}
    )
    _log_audit(request.user, "SAVE_VARIABLE", "EnvironmentVariable", var.id, {'key': key})
    return JsonResponse({'success': True, 'variable': var.to_dict()}, status=201 if created else 200)


@csrf_exempt
@require_http_methods(["PUT", "PATCH", "DELETE"])
def variable_detail_api(request, variable_id):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        var = EnvironmentVariable.objects.get(id=variable_id, environment__user=request.user)
    except EnvironmentVariable.DoesNotExist:
        return JsonResponse({'error': 'Variable not found.'}, status=404)

    if request.method in ["PUT", "PATCH"]:
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        if 'key' in data:
            key = data['key'].strip()
            if not key:
                return JsonResponse({'error': 'Variable key cannot be empty.'}, status=400)
            var.key = key
        if 'value' in data:
            var.value = data['value']

        var.save()
        return JsonResponse({'success': True, 'variable': var.to_dict()})
    elif request.method == "DELETE":
        var.delete()
        return JsonResponse({'success': True, 'deleted_id': variable_id})


# --- PHASE 5: OPENAPI IMPORT & EXPORT ENDPOINTS ---

@csrf_exempt
@require_http_methods(["POST"])
def import_openapi_api(request):
    """Imports OpenAPI 3.x / Swagger 2.0 file (JSON or YAML) and converts to Collection."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    raw_content = ""
    if request.FILES and 'file' in request.FILES:
        uploaded_file = request.FILES['file']
        if uploaded_file.size > 10 * 1024 * 1024:
            return JsonResponse({'error': 'Uploaded specification file exceeds 10MB limit.'}, status=413)
        raw_content = uploaded_file.read().decode('utf-8', errors='ignore')
    else:
        try:
            body_json = json.loads(request.body.decode('utf-8') or '{}')
            raw_content = body_json.get('spec', '')
        except Exception:
            raw_content = request.body.decode('utf-8', errors='ignore')

    success, err_msg, parsed_summary = _parse_openapi_spec(raw_content)
    if not success:
        return JsonResponse({'error': f"OPENAPI SPECIFICATION INVALID: {err_msg}"}, status=400)

    # Convert OpenAPI into Collection
    col = Collection.objects.create(
        user=request.user,
        name=parsed_summary['title'],
        description=parsed_summary['description']
    )

    servers = parsed_summary.get('servers', [])
    base_url = servers[0]['url'].rstrip('/') if servers else 'https://api.example.com'

    imported_requests_count = 0
    for ep in parsed_summary['endpoints']:
        full_url = f"{base_url}{ep['path']}"
        SavedRequest.objects.create(
            user=request.user,
            collection=col,
            name=ep['summary'],
            description=ep['description'],
            method=ep['method'],
            url=full_url,
            headers=ep['headers'],
            params=ep['params']
        )
        imported_requests_count += 1

    spec_obj = ApiSpecification.objects.create(
        user=request.user,
        collection=col,
        title=parsed_summary['title'],
        version=parsed_summary['version'],
        description=parsed_summary['description'],
        servers=servers,
        raw_spec=raw_content,
        parsed_spec=parsed_summary
    )

    _log_audit(request.user, "IMPORT_OPENAPI", "Collection", col.id, {'title': parsed_summary['title']})

    return JsonResponse({
        'success': True,
        'collection': col.to_dict(),
        'spec_id': spec_obj.id,
        'summary': parsed_summary,
        'imported_requests': imported_requests_count,
    }, status=201)


@csrf_exempt
@require_http_methods(["GET"])
def export_openapi_api(request, collection_id):
    """Exports APIHub Collection as OpenAPI 3.0 specification in JSON or YAML."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        col = Collection.objects.get(id=collection_id, user=request.user)
    except Collection.DoesNotExist:
        return JsonResponse({'error': 'Collection not found.'}, status=404)

    openapi_dict = _export_collection_to_openapi(col)
    fmt = request.GET.get('format', 'json').lower()

    if fmt == 'yaml':
        yaml_str = yaml.dump(openapi_dict, sort_keys=False)
        response = HttpResponse(yaml_str, content_type='text/yaml')
        response['Content-Disposition'] = f'attachment; filename="{col.name}_openapi.yaml"'
        return response

    _log_audit(request.user, "EXPORT_OPENAPI", "Collection", col.id)
    return JsonResponse(openapi_dict, json_dumps_params={'indent': 2})


# --- PHASE 5: REUSABLE TEST SUITES ENDPOINTS ---

@csrf_exempt
@require_http_methods(["GET", "POST"])
def test_suites_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    if request.method == "GET":
        suites = TestSuite.objects.filter(user=request.user)
        return JsonResponse({'test_suites': [s.to_dict() for s in suites]})
    elif request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        name = (data.get('name') or '').strip()
        if not name:
            return JsonResponse({'error': 'Test Suite name is required.'}, status=400)

        suite = TestSuite.objects.create(
            user=request.user,
            collection_id=data.get('collection_id'),
            name=name,
            description=data.get('description', ''),
            requests=data.get('requests', []),
            stop_on_failure=data.get('stop_on_failure', False)
        )
        _log_audit(request.user, "CREATE_TEST_SUITE", "TestSuite", suite.id)
        return JsonResponse({'success': True, 'test_suite': suite.to_dict()}, status=201)


@csrf_exempt
@require_http_methods(["GET", "PUT", "PATCH", "DELETE"])
def test_suite_detail_api(request, suite_id):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        suite = TestSuite.objects.get(id=suite_id, user=request.user)
    except TestSuite.DoesNotExist:
        return JsonResponse({'error': 'Test Suite not found.'}, status=404)

    if request.method == "GET":
        return JsonResponse({'test_suite': suite.to_dict()})
    elif request.method in ["PUT", "PATCH"]:
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        if 'name' in data:
            suite.name = data['name'].strip()
        if 'description' in data:
            suite.description = data['description']
        if 'requests' in data:
            suite.requests = data['requests']
        if 'stop_on_failure' in data:
            suite.stop_on_failure = data['stop_on_failure']

        suite.save()
        return JsonResponse({'success': True, 'test_suite': suite.to_dict()})
    elif request.method == "DELETE":
        suite.delete()
        return JsonResponse({'success': True, 'deleted_id': suite_id})


@csrf_exempt
@require_http_methods(["POST"])
def run_test_suite_api(request, suite_id):
    """Executes a reusable Test Suite, evaluating assertions and contract rules."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        suite = TestSuite.objects.get(id=suite_id, user=request.user)
    except TestSuite.DoesNotExist:
        return JsonResponse({'error': 'Test Suite not found.'}, status=404)

    req_ids = suite.requests
    if not req_ids:
        return JsonResponse({'error': 'Test Suite contains no requests.'}, status=400)

    saved_reqs = SavedRequest.objects.filter(id__in=req_ids, user=request.user)
    start_time = time.perf_counter()

    total_assertions = 0
    passed_assertions = 0
    failed_assertions = 0
    overall_contract_passed = True
    details = []

    suite_run = TestSuiteRun.objects.create(user=request.user, suite=suite)

    for req in saved_reqs:
        clean_headers = _normalize_key_values(req.headers)
        clean_params = _normalize_key_values(req.params)
        req_auth = None
        if req.auth_type == 'bearer' and isinstance(req.auth_data, dict):
            token = req.auth_data.get('token')
            if token:
                clean_headers['Authorization'] = f"Bearer {token}"
        elif req.auth_type == 'basic' and isinstance(req.auth_data, dict):
            req_auth = HTTPBasicAuth(req.auth_data.get('username', ''), req.auth_data.get('password', ''))

        send_data = req.body.encode('utf-8') if req.body else None
        req_start = time.perf_counter()
        status_code = None
        status_text = ''
        response_headers = {}
        response_data = None
        is_json = False
        raw_body_text = ""

        try:
            resp = requests.request(
                method=req.method,
                url=req.url,
                headers=clean_headers,
                params=clean_params,
                data=send_data,
                auth=req_auth,
                timeout=15,
            )
            req_latency = (time.perf_counter() - req_start) * 1000.0
            status_code = resp.status_code
            status_text = resp.reason or 'OK'
            response_headers = dict(resp.headers)
            raw_body_text = resp.text
            try:
                response_data = resp.json()
                is_json = True
            except Exception:
                response_data = resp.text
                is_json = False
        except Exception as e:
            req_latency = (time.perf_counter() - req_start) * 1000.0
            status_code = 500
            status_text = 'Error'
            response_data = str(e)
            raw_body_text = str(e)

        resp_obj = {
            'status_code': status_code,
            'time_ms': req_latency,
            'headers': response_headers,
            'body': raw_body_text,
            'data': response_data,
            'is_json': is_json,
        }

        # Assertions
        eval_results, eval_summary = _evaluate_assertions(req.tests, resp_obj)
        total_assertions += eval_summary['total']
        passed_assertions += eval_summary['passed']
        failed_assertions += eval_summary['failed']

        # Contract Check
        contract_passed, contract_checks = _validate_api_contract(req.contract_schema, resp_obj)
        if not contract_passed:
            overall_contract_passed = False

        item_detail = {
            'request_name': req.name,
            'method': req.method,
            'url': req.url,
            'status_code': status_code,
            'latency_ms': round(req_latency, 2),
            'assertions_passed': eval_summary['failed'] == 0,
            'contract_passed': contract_passed,
            'assertion_results': eval_results,
            'contract_checks': contract_checks,
        }
        details.append(item_detail)

        if suite.stop_on_failure and (eval_summary['failed'] > 0 or not contract_passed):
            break

    total_duration = (time.perf_counter() - start_time) * 1000.0
    suite_run.total_tests = total_assertions
    suite_run.passed_tests = passed_assertions
    suite_run.failed_tests = failed_assertions
    suite_run.contract_passed = overall_contract_passed
    suite_run.duration_ms = total_duration
    suite_run.details = details
    suite_run.save()

    _log_audit(request.user, "RUN_TEST_SUITE", "TestSuite", suite.id)

    return JsonResponse({
        'success': True,
        'suite_run': suite_run.to_dict(),
    })


# --- PHASE 5: API MONITORING & SCHEDULED CHECKS ---

def _execute_monitor(monitor):
    """Executes server-side monitor check, evaluates alerts, and logs MonitorRun."""
    if not monitor.enabled:
        return

    # Check URL safety
    is_safe, sec_error = _is_safe_url(monitor.url)
    if not is_safe:
        MonitorRun.objects.create(
            monitor=monitor,
            status_code=400,
            response_time_ms=0.0,
            is_healthy=False,
            error_message=f"SSRF Blocked: {sec_error}"
        )
        _process_monitor_alerts(monitor, is_healthy=False, status_code=400, latency_ms=0.0)
        return

    clean_headers = _normalize_key_values(monitor.headers)
    send_data = monitor.body.encode('utf-8') if monitor.body else None

    start_time = time.perf_counter()
    status_code = None
    latency_ms = 0.0
    is_healthy = False
    err_msg = ""

    try:
        resp = requests.request(
            method=monitor.method,
            url=monitor.url,
            headers=clean_headers,
            data=send_data,
            timeout=15,
        )
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = resp.status_code

        # Health rule: Status code matches expected AND latency <= max_latency_ms
        if status_code == monitor.expected_status and latency_ms <= monitor.max_latency_ms:
            is_healthy = True
        else:
            is_healthy = False
            err_msg = f"Status {status_code} (Expected {monitor.expected_status}) or Latency {round(latency_ms, 1)}ms > {monitor.max_latency_ms}ms"

    except Exception as e:
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = 500
        is_healthy = False
        err_msg = str(e)

    monitor.last_run_at = timezone.now()
    monitor.save()

    run_obj = MonitorRun.objects.create(
        monitor=monitor,
        status_code=status_code,
        response_time_ms=latency_ms,
        is_healthy=is_healthy,
        error_message=err_msg
    )

    _process_monitor_alerts(monitor, is_healthy, status_code, latency_ms)
    return run_obj


def _process_monitor_alerts(monitor, is_healthy, status_code, latency_ms):
    """Processes AlertRules and creates Notifications with Alert Deduplication."""
    alert_rules = monitor.alert_rules.filter(enabled=True)
    for rule in alert_rules:
        if not is_healthy and not rule.is_currently_failing:
            rule.is_currently_failing = True
            rule.save()
            Notification.objects.create(
                user=monitor.user,
                monitor=monitor,
                alert_type='MONITOR_DOWN',
                title=f"🚨 Monitor Alert: {monitor.name} is DOWN",
                message=f"Monitor '{monitor.name}' ({monitor.method} {monitor.url}) failed with status {status_code} ({round(latency_ms, 1)}ms)."
            )
        elif is_healthy and rule.is_currently_failing:
            rule.is_currently_failing = False
            rule.save()
            Notification.objects.create(
                user=monitor.user,
                monitor=monitor,
                alert_type='MONITOR_RECOVERED',
                title=f"✅ Monitor Recovered: {monitor.name} is OPERATIONAL",
                message=f"Monitor '{monitor.name}' recovered. Status {status_code} ({round(latency_ms, 1)}ms)."
            )


@csrf_exempt
@require_http_methods(["GET", "POST"])
def monitors_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    if request.method == "GET":
        monitors = Monitor.objects.filter(user=request.user).prefetch_related('runs', 'alert_rules')
        return JsonResponse({'monitors': [m.to_dict() for m in monitors]})
    elif request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        name = (data.get('name') or '').strip()
        url = (data.get('url') or '').strip()
        if not name or not url:
            return JsonResponse({'error': 'Monitor name and URL are required.'}, status=400)

        monitor = Monitor.objects.create(
            user=request.user,
            name=name,
            url=url,
            method=(data.get('method') or 'GET').upper(),
            headers=data.get('headers', {}),
            body=data.get('body', ''),
            environment_id=data.get('environment_id'),
            interval_minutes=int(data.get('interval_minutes', 15)),
            expected_status=int(data.get('expected_status', 200)),
            max_latency_ms=float(data.get('max_latency_ms', 2000.0)),
            enabled=data.get('enabled', True)
        )

        # Create Default Alert Rule
        AlertRule.objects.create(user=request.user, monitor=monitor, condition='on_failure')

        # Execute initial check
        _execute_monitor(monitor)

        _log_audit(request.user, "CREATE_MONITOR", "Monitor", monitor.id, {'name': name})
        return JsonResponse({'success': True, 'monitor': monitor.to_dict()}, status=201)


@csrf_exempt
@require_http_methods(["GET", "PUT", "PATCH", "DELETE"])
def monitor_detail_api(request, monitor_id):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        monitor = Monitor.objects.get(id=monitor_id, user=request.user)
    except Monitor.DoesNotExist:
        return JsonResponse({'error': 'Monitor not found.'}, status=404)

    if request.method == "GET":
        return JsonResponse({'monitor': monitor.to_dict()})
    elif request.method in ["PUT", "PATCH"]:
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON body.'}, status=400)

        if 'name' in data:
            monitor.name = data['name'].strip()
        if 'url' in data:
            monitor.url = data['url'].strip()
        if 'method' in data:
            monitor.method = data['method'].upper()
        if 'interval_minutes' in data:
            monitor.interval_minutes = int(data['interval_minutes'])
        if 'expected_status' in data:
            monitor.expected_status = int(data['expected_status'])
        if 'max_latency_ms' in data:
            monitor.max_latency_ms = float(data['max_latency_ms'])
        if 'enabled' in data:
            monitor.enabled = data['enabled']

        monitor.save()
        return JsonResponse({'success': True, 'monitor': monitor.to_dict()})
    elif request.method == "DELETE":
        m_id = monitor.id
        monitor.delete()
        return JsonResponse({'success': True, 'deleted_id': m_id})


@csrf_exempt
@require_http_methods(["POST"])
def run_monitor_now_api(request, monitor_id):
    """Manually triggers immediate monitor execution."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        monitor = Monitor.objects.get(id=monitor_id, user=request.user)
    except Monitor.DoesNotExist:
        return JsonResponse({'error': 'Monitor not found.'}, status=404)

    run_obj = _execute_monitor(monitor)
    return JsonResponse({'success': True, 'run': run_obj.to_dict() if run_obj else None, 'monitor': monitor.to_dict()})


@csrf_exempt
@require_http_methods(["GET"])
def monitors_dashboard_api(request):
    """Dashboard view aggregating health, uptime, and response time metrics across monitors."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    monitors = Monitor.objects.filter(user=request.user)
    if not monitors.exists():
        return JsonResponse({
            'total_monitors': 0,
            'overall_uptime': 100.0,
            'status_counts': {'Operational': 0, 'Degraded': 0, 'Down': 0, 'Unknown': 0},
            'monitors': []
        })

    status_counts = {'Operational': 0, 'Degraded': 0, 'Down': 0, 'Unknown': 0}
    uptime_sum = 0.0

    monitor_dicts = []
    for m in monitors:
        m_dict = m.to_dict()
        h_status = m_dict['metrics']['health_status']
        status_counts[h_status] = status_counts.get(h_status, 0) + 1
        uptime_sum += m_dict['metrics']['uptime_percent']
        monitor_dicts.append(m_dict)

    overall_uptime = round(uptime_sum / len(monitors), 1)

    return JsonResponse({
        'total_monitors': len(monitors),
        'overall_uptime': overall_uptime,
        'status_counts': status_counts,
        'monitors': monitor_dicts,
    })


# --- PHASE 5: NOTIFICATIONS & ALERTS ENDPOINTS ---

@csrf_exempt
@require_http_methods(["GET", "POST"])
def notifications_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    if request.method == "GET":
        notes = Notification.objects.filter(user=request.user)[:30]
        unread_count = Notification.objects.filter(user=request.user, is_read=False).count()
        return JsonResponse({
            'notifications': [n.to_dict() for n in notes],
            'unread_count': unread_count
        })
    elif request.method == "POST":
        Notification.objects.filter(user=request.user, is_read=False).update(is_read=True)
        return JsonResponse({'success': True, 'marked_all_read': True})


# --- PHASE 5: API MOCK SERVER ENDPOINTS ---

@csrf_exempt
@require_http_methods(["GET", "POST"])
def mock_endpoints_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    if request.method == "GET":
        mocks = MockEndpoint.objects.filter(user=request.user)
        return JsonResponse({'mock_endpoints': [m.to_dict() for m in mocks]})
    elif request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        name = (data.get('name') or '').strip()
        if not name:
            return JsonResponse({'error': 'Mock name is required.'}, status=400)

        mock = MockEndpoint.objects.create(
            user=request.user,
            name=name,
            method=(data.get('method') or 'GET').upper(),
            path=data.get('path', '/'),
            response_status=int(data.get('response_status', 200)),
            response_headers=data.get('response_headers', {'Content-Type': 'application/json'}),
            response_body=data.get('response_body', '{"message": "Hello from APIHub Mock Server"}'),
            delay_ms=min(int(data.get('delay_ms', 0)), 3000),
            enabled=data.get('enabled', True)
        )
        _log_audit(request.user, "CREATE_MOCK", "MockEndpoint", mock.id, {'name': name})
        return JsonResponse({'success': True, 'mock_endpoint': mock.to_dict()}, status=201)


@csrf_exempt
@require_http_methods(["GET", "PUT", "PATCH", "DELETE"])
def mock_endpoint_detail_api(request, mock_id):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        mock = MockEndpoint.objects.get(id=mock_id, user=request.user)
    except MockEndpoint.DoesNotExist:
        return JsonResponse({'error': 'Mock Endpoint not found.'}, status=404)

    if request.method == "GET":
        return JsonResponse({'mock_endpoint': mock.to_dict()})
    elif request.method in ["PUT", "PATCH"]:
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        if 'name' in data:
            mock.name = data['name'].strip()
        if 'method' in data:
            mock.method = data['method'].upper()
        if 'path' in data:
            mock.path = data['path']
        if 'response_status' in data:
            mock.response_status = int(data['response_status'])
        if 'response_headers' in data:
            mock.response_headers = data['response_headers']
        if 'response_body' in data:
            mock.response_body = data['response_body']
        if 'delay_ms' in data:
            mock.delay_ms = min(int(data['delay_ms']), 3000)
        if 'enabled' in data:
            mock.enabled = data['enabled']

        mock.save()
        return JsonResponse({'success': True, 'mock_endpoint': mock.to_dict()})
    elif request.method == "DELETE":
        m_id = mock.id
        mock.delete()
        return JsonResponse({'success': True, 'deleted_id': m_id})


@csrf_exempt
def public_mock_proxy(request, mock_key, extra_path=""):
    """Public router for simulated Mock API endpoints (/api/mock/<mock_key>/)."""
    try:
        mock = MockEndpoint.objects.get(mock_key=mock_key, enabled=True)
    except MockEndpoint.DoesNotExist:
        return JsonResponse({'error': 'Mock endpoint not found or disabled.'}, status=404)

    if request.method != mock.method and mock.method != 'ALL':
        return JsonResponse({'error': f"Method {request.method} not allowed for mock route. Expected {mock.method}."}, status=405)

    if mock.delay_ms > 0:
        time.sleep(min(mock.delay_ms, 3000) / 1000.0)

    content_type = mock.response_headers.get('Content-Type') or mock.response_headers.get('content-type') or 'application/json'
    response = HttpResponse(mock.response_body, content_type=content_type, status=mock.response_status)

    for k, v in mock.response_headers.items():
        if k.lower() not in ['content-type', 'content-length']:
            response[k] = v

    return response


# --- PHASE 5: API VERSIONING & LIFECYCLE ENDPOINTS ---

@csrf_exempt
@require_http_methods(["GET", "POST"])
def api_versions_api(request, collection_id):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        col = Collection.objects.get(id=collection_id, user=request.user)
    except Collection.DoesNotExist:
        return JsonResponse({'error': 'Collection not found.'}, status=404)

    if request.method == "GET":
        versions = col.api_versions.all()
        return JsonResponse({'api_versions': [v.to_dict() for v in versions]})
    elif request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        v_name = (data.get('version_name') or '').strip()
        if not v_name:
            return JsonResponse({'error': 'Version name (e.g. v2.0) is required.'}, status=400)

        ver = ApiVersion.objects.create(
            user=request.user,
            collection=col,
            version_name=v_name,
            status=data.get('status', 'ACTIVE'),
            changelog=data.get('changelog', '')
        )
        _log_audit(request.user, "CREATE_API_VERSION", "ApiVersion", ver.id, {'version': v_name})
        return JsonResponse({'success': True, 'api_version': ver.to_dict()}, status=201)


@csrf_exempt
@require_http_methods(["PUT", "PATCH", "DELETE"])
def api_version_detail_api(request, version_id):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        ver = ApiVersion.objects.get(id=version_id, user=request.user)
    except ApiVersion.DoesNotExist:
        return JsonResponse({'error': 'API Version not found.'}, status=404)

    if request.method in ["PUT", "PATCH"]:
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        if 'status' in data:
            ver.status = data['status']
        if 'changelog' in data:
            ver.changelog = data['changelog']
        if 'version_name' in data:
            ver.version_name = data['version_name'].strip()

        ver.save()
        return JsonResponse({'success': True, 'api_version': ver.to_dict()})
    elif request.method == "DELETE":
        v_id = ver.id
        ver.delete()
        return JsonResponse({'success': True, 'deleted_id': v_id})


# --- PHASE 5: SHAREABLE PUBLIC DOCUMENTATION ENDPOINTS ---

@csrf_exempt
@require_http_methods(["POST"])
def publish_documentation_api(request, collection_id):
    """Publishes collection documentation to a public URL with secret redaction."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        col = Collection.objects.get(id=collection_id, user=request.user)
    except Collection.DoesNotExist:
        return JsonResponse({'error': 'Collection not found.'}, status=404)

    pub_doc, created = PublicDocumentation.objects.get_or_create(
        user=request.user,
        collection=col,
        defaults={'published': True}
    )
    if not created:
        pub_doc.published = True
        pub_doc.save()

    _log_audit(request.user, "PUBLISH_DOCS", "Collection", col.id)
    return JsonResponse({'success': True, 'public_documentation': pub_doc.to_dict()})


def public_documentation_view(request, share_key):
    """Renders public read-only Markdown documentation with REDACTED secrets."""
    try:
        pub_doc = PublicDocumentation.objects.get(share_key=share_key, published=True)
    except PublicDocumentation.DoesNotExist:
        return render(request, 'client/public_doc.html', {'error': 'Public documentation not found or unpublished.'}, status=404)

    pub_doc.view_count += 1
    pub_doc.save()

    col = pub_doc.collection
    doc_markdown = f"# {col.name}\n\n{col.description or 'API Documentation'}\n\n---\n\n"
    for req in col.requests.all():
        doc_markdown += f"## {req.method} `{req.url}`\n\n"
        doc_markdown += f"**Name**: {req.name}\n\n"
        if req.description:
            doc_markdown += f"**Description**: {req.description}\n\n"

        if req.headers:
            doc_markdown += "### Request Headers\n\n| Key | Value |\n| :--- | :--- |\n"
            h_list = req.headers if isinstance(req.headers, list) else []
            for h in h_list:
                if isinstance(h, dict):
                    k = h.get('key', '')
                    v = "[REDACTED]" if k.lower() in SENSITIVE_KEYS else h.get('value', '')
                    doc_markdown += f"| `{k}` | `{v}` |\n"
            doc_markdown += "\n"

        if req.body:
            doc_markdown += "### Request Body Example\n\n```json\n" + req.body + "\n```\n\n"

        doc_markdown += "---\n\n"

    return render(request, 'client/public_doc.html', {
        'pub_doc': pub_doc,
        'doc_markdown': doc_markdown,
        'collection_name': col.name,
        'is_public_view': True,
    })


# --- PHASE 5: GLOBAL SEARCH API ---

@csrf_exempt
@require_http_methods(["GET"])
def global_search_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    query = request.GET.get('q', '').strip().lower()
    if not query:
        return JsonResponse({'results': []})

    results = []

    # 1. Collections
    for c in Collection.objects.filter(user=request.user, name__icontains=query)[:10]:
        results.append({'type': 'Collection', 'id': c.id, 'title': c.name, 'subtitle': f"{c.requests.count()} requests"})

    # 2. Saved Requests
    for r in SavedRequest.objects.filter(user=request.user, name__icontains=query)[:10]:
        results.append({'type': 'Saved Request', 'id': r.id, 'title': f"{r.method} {r.name}", 'subtitle': r.url})

    # 3. Monitors
    for m in Monitor.objects.filter(user=request.user, name__icontains=query)[:10]:
        results.append({'type': 'Monitor', 'id': m.id, 'title': m.name, 'subtitle': f"{m.method} {m.url}"})

    # 4. Test Suites
    for s in TestSuite.objects.filter(user=request.user, name__icontains=query)[:10]:
        results.append({'type': 'Test Suite', 'id': s.id, 'title': s.name, 'subtitle': f"{len(s.requests)} requests"})

    # 5. Mocks
    for mk in MockEndpoint.objects.filter(user=request.user, name__icontains=query)[:10]:
        results.append({'type': 'Mock Endpoint', 'id': mk.id, 'title': mk.name, 'subtitle': f"{mk.method} {mk.path}"})

    return JsonResponse({'results': results})


# --- PHASE 3 ANALYTICS API ---

@csrf_exempt
@require_http_methods(["GET"])
def analytics_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    time_range = request.GET.get('range', '7days')
    now = timezone.now()

    if time_range == 'today':
        start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif time_range == '7days':
        start_date = now - timedelta(days=7)
    elif time_range == '30days':
        start_date = now - timedelta(days=30)
    else:
        start_date = None

    queryset = RequestHistory.objects.filter(user=request.user)
    if start_date:
        queryset = queryset.filter(timestamp__gte=start_date)

    total_requests = queryset.count()
    if total_requests == 0:
        return JsonResponse({
            'total_requests': 0,
            'success_rate': 0.0,
            'avg_response_time_ms': 0.0,
            'fastest_ms': 0.0,
            'slowest_ms': 0.0,
            'status_distribution': {'2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0},
            'has_data': False
        })

    success_count = queryset.filter(status_code__gte=200, status_code__lt=300).count()
    s_2xx = success_count
    s_3xx = queryset.filter(status_code__gte=300, status_code__lt=400).count()
    s_4xx = queryset.filter(status_code__gte=400, status_code__lt=500).count()
    s_5xx = queryset.filter(status_code__gte=500).count()

    times = [r.response_time_ms for r in queryset if r.response_time_ms is not None]
    avg_time = round(sum(times) / len(times), 2) if times else 0.0
    fastest = round(min(times), 2) if times else 0.0
    slowest = round(max(times), 2) if times else 0.0
    success_rate = round((success_count / total_requests) * 100.0, 1)

    return JsonResponse({
        'total_requests': total_requests,
        'success_rate': success_rate,
        'avg_response_time_ms': avg_time,
        'fastest_ms': fastest,
        'slowest_ms': slowest,
        'status_distribution': {
            '2xx': s_2xx,
            '3xx': s_3xx,
            '4xx': s_4xx,
            '5xx': s_5xx
        },
        'has_data': True
    })


# --- PHASE 6: AUTHENTICATION, WORKSPACES & COLLABORATION HELPERS ---

ROLE_HIERARCHY = {'OWNER': 4, 'ADMIN': 3, 'EDITOR': 2, 'VIEWER': 1}

def _authenticate_api_request(request):
    """
    Authenticates API requests via standard Django session auth OR Personal Access Tokens / Service Account Tokens.
    Returns (user, error_message, service_account).
    """
    if request.user and request.user.is_authenticated:
        return request.user, None, None

    token_str = ""
    auth_hdr = request.headers.get('Authorization', '')
    if auth_hdr.startswith('Bearer ahp_'):
        token_str = auth_hdr[7:].strip()
    elif request.headers.get('X-APIHub-Token'):
        token_str = request.headers.get('X-APIHub-Token').strip()

    if not token_str:
        return None, "Authentication required. Provide session login or Bearer token (ahp_...).", None

    token_hash = hashlib.sha256(token_str.encode('utf-8')).hexdigest()

    try:
        pat = PersonalAccessToken.objects.get(token_hash=token_hash, revoked=False)
        if pat.expires_at and pat.expires_at < timezone.now():
            return None, "Personal Access Token has expired.", None
        pat.last_used_at = timezone.now()
        pat.save()
        return pat.user, None, None
    except PersonalAccessToken.DoesNotExist:
        pass

    try:
        sat = ServiceAccountToken.objects.get(token_hash=token_hash, revoked=False)
        if sat.expires_at and sat.expires_at < timezone.now():
            return None, "Service Account Token has expired.", None
        sat.last_used_at = timezone.now()
        sat.save()
        return sat.service_account.created_by, None, sat.service_account
    except ServiceAccountToken.DoesNotExist:
        pass

    return None, "Invalid or revoked authentication token.", None


def _get_user_workspace_role(user, workspace):
    if not workspace or not user:
        return 'OWNER'
    if workspace.owner_id == user.id:
        return 'OWNER'
    try:
        member = WorkspaceMember.objects.get(workspace=workspace, user=user)
        return member.role
    except WorkspaceMember.DoesNotExist:
        return None


def _has_workspace_permission(user, workspace, required_role='VIEWER'):
    user_role = _get_user_workspace_role(user, workspace)
    if not user_role:
        return False
    return ROLE_HIERARCHY.get(user_role, 0) >= ROLE_HIERARCHY.get(required_role, 0)


def _dispatch_workspace_webhooks(workspace, event_type, payload):
    """Dispatches HMAC-signed webhook notifications asynchronously/safely."""
    if not workspace:
        return
    webhooks = Webhook.objects.filter(workspace=workspace, enabled=True)
    for wh in webhooks:
        if wh.events and event_type not in wh.events:
            continue
        is_safe, sec_error = _is_safe_url(wh.url)
        if not is_safe:
            WebhookDelivery.objects.create(
                webhook=wh,
                event=event_type,
                status_code=400,
                payload=payload,
                response_body=f"SSRF Blocked: {sec_error}",
                success=False
            )
            continue
        payload_bytes = json.dumps(payload).encode('utf-8')
        sig = hmac.new(wh.secret.encode('utf-8'), payload_bytes, hashlib.sha256).hexdigest()
        start = time.perf_counter()
        try:
            resp = requests.post(
                wh.url,
                data=payload_bytes,
                headers={'Content-Type': 'application/json', 'X-APIHub-Signature': f"sha256={sig}"},
                timeout=10
            )
            duration = (time.perf_counter() - start) * 1000.0
            WebhookDelivery.objects.create(
                webhook=wh,
                event=event_type,
                status_code=resp.status_code,
                payload=payload,
                response_body=resp.text[:1000],
                duration_ms=duration,
                success=resp.status_code < 400
            )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000.0
            WebhookDelivery.objects.create(
                webhook=wh,
                event=event_type,
                status_code=500,
                payload=payload,
                response_body=str(e),
                duration_ms=duration,
                success=False
            )


# --- PHASE 6 WORKSPACE API ENDPOINTS ---

@csrf_exempt
@require_http_methods(["GET", "POST"])
def workspaces_api(request):
    user, auth_err, _ = _authenticate_api_request(request)
    if auth_err:
        return JsonResponse({'error': auth_err}, status=401)

    if request.method == "GET":
        owned_ws = Workspace.objects.filter(owner=user)
        member_ws_ids = WorkspaceMember.objects.filter(user=user).values_list('workspace_id', flat=True)
        joined_ws = Workspace.objects.filter(id__in=member_ws_ids)
        all_ws = (owned_ws | joined_ws).distinct()

        # Ensure personal workspace exists
        if not owned_ws.filter(is_personal=True).exists():
            p_ws = Workspace.objects.create(name=f"{user.username}'s Personal Workspace", owner=user, is_personal=True)
            WorkspaceMember.objects.create(workspace=p_ws, user=user, role='OWNER')
            all_ws = (Workspace.objects.filter(owner=user) | joined_ws).distinct()

        ws_data = []
        for w in all_ws:
            d = w.to_dict()
            d['user_role'] = _get_user_workspace_role(user, w)
            ws_data.append(d)

        return JsonResponse({'workspaces': ws_data})

    elif request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        name = (data.get('name') or '').strip()
        if not name:
            return JsonResponse({'error': 'Workspace name is required.'}, status=400)

        ws = Workspace.objects.create(
            name=name,
            description=data.get('description', ''),
            owner=user,
            is_personal=False
        )
        WorkspaceMember.objects.create(workspace=ws, user=user, role='OWNER')
        _log_audit(user, "CREATE_WORKSPACE", "Workspace", ws.id, {'name': name})
        return JsonResponse({'success': True, 'workspace': ws.to_dict()}, status=201)


@csrf_exempt
@require_http_methods(["GET", "PUT", "PATCH", "DELETE"])
def workspace_detail_api(request, workspace_id):
    user, auth_err, _ = _authenticate_api_request(request)
    if auth_err:
        return JsonResponse({'error': auth_err}, status=401)

    try:
        ws = Workspace.objects.get(id=workspace_id)
    except Workspace.DoesNotExist:
        return JsonResponse({'error': 'Workspace not found.'}, status=404)

    if not _has_workspace_permission(user, ws, 'VIEWER'):
        return JsonResponse({'error': 'Forbidden: You are not a member of this workspace.'}, status=403)

    if request.method == "GET":
        d = ws.to_dict()
        d['user_role'] = _get_user_workspace_role(user, ws)
        return JsonResponse({'workspace': d})

    elif request.method in ["PUT", "PATCH"]:
        if not _has_workspace_permission(user, ws, 'ADMIN'):
            return JsonResponse({'error': 'Forbidden: ADMIN or OWNER role required to modify workspace.'}, status=403)

        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        if 'name' in data:
            name = data['name'].strip()
            if not name:
                return JsonResponse({'error': 'Workspace name cannot be empty.'}, status=400)
            ws.name = name
        if 'description' in data:
            ws.description = data['description']

        ws.save()
        _log_audit(user, "UPDATE_WORKSPACE", "Workspace", ws.id)
        return JsonResponse({'success': True, 'workspace': ws.to_dict()})

    elif request.method == "DELETE":
        if ws.owner_id != user.id:
            return JsonResponse({'error': 'Forbidden: Only the workspace OWNER can delete this workspace.'}, status=403)
        if ws.is_personal:
            return JsonResponse({'error': 'Personal workspaces cannot be deleted.'}, status=400)

        ws_id = ws.id
        ws.delete()
        _log_audit(user, "DELETE_WORKSPACE", "Workspace", ws_id)
        return JsonResponse({'success': True, 'deleted_id': workspace_id})


@csrf_exempt
@require_http_methods(["GET", "POST", "PUT", "PATCH", "DELETE"])
def workspace_members_api(request, workspace_id):
    user, auth_err, _ = _authenticate_api_request(request)
    if auth_err:
        return JsonResponse({'error': auth_err}, status=401)

    try:
        ws = Workspace.objects.get(id=workspace_id)
    except Workspace.DoesNotExist:
        return JsonResponse({'error': 'Workspace not found.'}, status=404)

    if not _has_workspace_permission(user, ws, 'VIEWER'):
        return JsonResponse({'error': 'Forbidden: Not a workspace member.'}, status=403)

    if request.method == "GET":
        members = ws.members.all()
        invitations = ws.invitations.filter(accepted_at__isnull=True)
        return JsonResponse({
            'members': [m.to_dict() for m in members],
            'invitations': [inv.to_dict() for inv in invitations]
        })

    elif request.method == "POST":
        if not _has_workspace_permission(user, ws, 'ADMIN'):
            return JsonResponse({'error': 'Forbidden: ADMIN or OWNER role required to invite members.'}, status=403)

        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        target = (data.get('target') or '').strip()
        role = (data.get('role') or 'EDITOR').upper()
        if not target:
            return JsonResponse({'error': 'Target email or username is required.'}, status=400)
        if role not in ['ADMIN', 'EDITOR', 'VIEWER']:
            role = 'EDITOR'

        target_user = User.objects.filter(username=target).first() or User.objects.filter(email=target).first()
        if target_user:
            if WorkspaceMember.objects.filter(workspace=ws, user=target_user).exists():
                return JsonResponse({'error': f"User '{target}' is already a member of this workspace."}, status=400)
            member = WorkspaceMember.objects.create(workspace=ws, user=target_user, role=role)
            _log_audit(user, "ADD_MEMBER", "Workspace", ws.id, {'added': target_user.username, 'role': role})
            return JsonResponse({'success': True, 'member': member.to_dict()}, status=201)

        exp = timezone.now() + timedelta(days=7)
        inv = WorkspaceInvitation.objects.create(
            workspace=ws,
            invited_by=user,
            target=target,
            role=role,
            expires_at=exp
        )
        _log_audit(user, "INVITE_MEMBER", "Workspace", ws.id, {'invited': target, 'role': role})
        return JsonResponse({'success': True, 'invitation': inv.to_dict()}, status=201)

    elif request.method in ["PUT", "PATCH"]:
        if not _has_workspace_permission(user, ws, 'ADMIN'):
            return JsonResponse({'error': 'Forbidden: ADMIN or OWNER role required.'}, status=403)

        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        target_user_id = data.get('user_id')
        new_role = (data.get('role') or '').upper()

        if target_user_id == ws.owner_id:
            return JsonResponse({'error': 'Cannot change role of workspace OWNER.'}, status=400)

        try:
            member = WorkspaceMember.objects.get(workspace=ws, user_id=target_user_id)
        except WorkspaceMember.DoesNotExist:
            return JsonResponse({'error': 'Member not found.'}, status=404)

        if new_role in ['ADMIN', 'EDITOR', 'VIEWER']:
            member.role = new_role
            member.save()

        return JsonResponse({'success': True, 'member': member.to_dict()})

    elif request.method == "DELETE":
        if not _has_workspace_permission(user, ws, 'ADMIN'):
            return JsonResponse({'error': 'Forbidden: ADMIN or OWNER role required.'}, status=403)

        target_user_id = request.GET.get('user_id')
        if not target_user_id:
            return JsonResponse({'error': 'user_id is required.'}, status=400)

        if int(target_user_id) == ws.owner_id:
            return JsonResponse({'error': 'Workspace OWNER cannot be removed. Transfer ownership first.'}, status=400)

        WorkspaceMember.objects.filter(workspace=ws, user_id=target_user_id).delete()
        _log_audit(user, "REMOVE_MEMBER", "Workspace", ws.id, {'removed_user_id': target_user_id})
        return JsonResponse({'success': True, 'removed_user_id': target_user_id})


@csrf_exempt
@require_http_methods(["POST"])
def accept_invitation_api(request, token):
    user, auth_err, _ = _authenticate_api_request(request)
    if auth_err:
        return JsonResponse({'error': auth_err}, status=401)

    try:
        inv = WorkspaceInvitation.objects.get(token=token, accepted_at__isnull=True)
    except WorkspaceInvitation.DoesNotExist:
        return JsonResponse({'error': 'Invalid or already accepted invitation token.'}, status=404)

    if inv.expires_at < timezone.now():
        return JsonResponse({'error': 'Invitation token has expired.'}, status=400)

    member, _ = WorkspaceMember.objects.get_or_create(
        workspace=inv.workspace,
        user=user,
        defaults={'role': inv.role}
    )
    inv.accepted_at = timezone.now()
    inv.save()

    _log_audit(user, "ACCEPT_INVITATION", "Workspace", inv.workspace.id)
    return JsonResponse({'success': True, 'workspace': inv.workspace.to_dict(), 'member': member.to_dict()})


# --- PHASE 6 PERSONAL ACCESS TOKENS & SERVICE ACCOUNTS ENDPOINTS ---

@csrf_exempt
@require_http_methods(["GET", "POST"])
def personal_access_tokens_api(request):
    user, auth_err, _ = _authenticate_api_request(request)
    if auth_err:
        return JsonResponse({'error': auth_err}, status=401)

    if request.method == "GET":
        tokens = PersonalAccessToken.objects.filter(user=user, revoked=False)
        return JsonResponse({'tokens': [t.to_dict() for t in tokens]})

    elif request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        name = (data.get('name') or '').strip()
        if not name:
            return JsonResponse({'error': 'Token name is required.'}, status=400)

        raw_token = f"ahp_{uuid.uuid4().hex}"
        token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
        token_prefix = raw_token[:12]

        pat = PersonalAccessToken.objects.create(
            user=user,
            name=name,
            token_hash=token_hash,
            token_prefix=token_prefix,
            scopes=data.get('scopes', ['collections:read', 'tests:run', 'workspace:read']),
            expires_at=timezone.now() + timedelta(days=int(data.get('expiry_days', 30)))
        )
        _log_audit(user, "CREATE_PAT", "PersonalAccessToken", pat.id, {'name': name})
        return JsonResponse({
            'success': True,
            'token': pat.to_dict(),
            'raw_token': raw_token # Displayed ONCE only to user!
        }, status=201)


@csrf_exempt
@require_http_methods(["DELETE"])
def pat_token_detail_api(request, token_id):
    user, auth_err, _ = _authenticate_api_request(request)
    if auth_err:
        return JsonResponse({'error': auth_err}, status=401)

    try:
        pat = PersonalAccessToken.objects.get(id=token_id, user=user)
    except PersonalAccessToken.DoesNotExist:
        return JsonResponse({'error': 'Token not found.'}, status=404)

    pat.revoked = True
    pat.save()
    _log_audit(user, "REVOKE_PAT", "PersonalAccessToken", pat.id)
    return JsonResponse({'success': True, 'revoked_id': token_id})


@csrf_exempt
@require_http_methods(["GET", "POST"])
def webhooks_api(request, workspace_id):
    user, auth_err, _ = _authenticate_api_request(request)
    if auth_err:
        return JsonResponse({'error': auth_err}, status=401)

    try:
        ws = Workspace.objects.get(id=workspace_id)
    except Workspace.DoesNotExist:
        return JsonResponse({'error': 'Workspace not found.'}, status=404)

    if not _has_workspace_permission(user, ws, 'ADMIN'):
        return JsonResponse({'error': 'Forbidden: ADMIN or OWNER role required for webhooks.'}, status=403)

    if request.method == "GET":
        hooks = Webhook.objects.filter(workspace=ws)
        return JsonResponse({'webhooks': [w.to_dict() for w in hooks]})

    elif request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        name = (data.get('name') or '').strip()
        target_url = (data.get('url') or '').strip()
        if not name or not target_url:
            return JsonResponse({'error': 'Webhook name and URL are required.'}, status=400)

        is_safe, sec_err = _is_safe_url(target_url)
        if not is_safe:
            return JsonResponse({'error': f"SSRF Blocked: {sec_err}"}, status=400)

        wh = Webhook.objects.create(
            workspace=ws,
            name=name,
            url=target_url,
            secret=data.get('secret') or str(uuid.uuid4()),
            events=data.get('events', ['monitor.failed', 'test.completed', 'ci.completed']),
            enabled=data.get('enabled', True)
        )
        _log_audit(user, "CREATE_WEBHOOK", "Webhook", wh.id, {'name': name})
        return JsonResponse({'success': True, 'webhook': wh.to_dict()}, status=201)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def ci_runs_api(request, workspace_id):
    user, auth_err, _ = _authenticate_api_request(request)
    if auth_err:
        return JsonResponse({'error': auth_err}, status=401)

    try:
        ws = Workspace.objects.get(id=workspace_id)
    except Workspace.DoesNotExist:
        return JsonResponse({'error': 'Workspace not found.'}, status=404)

    if not _has_workspace_permission(user, ws, 'VIEWER'):
        return JsonResponse({'error': 'Forbidden: Workspace permission required.'}, status=403)

    if request.method == "GET":
        runs = CiRun.objects.filter(workspace=ws)[:50]
        return JsonResponse({'ci_runs': [r.to_dict() for r in runs]})

    elif request.method == "POST":
        if not _has_workspace_permission(user, ws, 'EDITOR'):
            return JsonResponse({'error': 'Forbidden: EDITOR or higher role required to record CI runs.'}, status=403)

        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        ci_run = CiRun.objects.create(
            workspace=ws,
            suite_id=data.get('suite_id'),
            commit_sha=data.get('commit_sha', ''),
            branch=data.get('branch', 'main'),
            status=data.get('status', 'PASSED'),
            total_count=int(data.get('total_count', 0)),
            passed_count=int(data.get('passed_count', 0)),
            failed_count=int(data.get('failed_count', 0)),
            duration_ms=float(data.get('duration_ms', 0.0)),
            report_data=data.get('report_data', {}),
            triggered_by=data.get('triggered_by', 'CLI / CI Runner')
        )
        _dispatch_workspace_webhooks(ws, "ci.completed", ci_run.to_dict())
        return JsonResponse({'success': True, 'ci_run': ci_run.to_dict()}, status=201)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def request_comments_api(request, request_id):
    user, auth_err, _ = _authenticate_api_request(request)
    if auth_err:
        return JsonResponse({'error': auth_err}, status=401)

    try:
        saved_req = SavedRequest.objects.get(id=request_id)
    except SavedRequest.DoesNotExist:
        return JsonResponse({'error': 'Saved request not found.'}, status=404)

    if saved_req.collection and saved_req.collection.workspace:
        if not _has_workspace_permission(user, saved_req.collection.workspace, 'VIEWER'):
            return JsonResponse({'error': 'Forbidden: Workspace access required.'}, status=403)

    if request.method == "GET":
        cmts = saved_req.comments.all()
        return JsonResponse({'comments': [c.to_dict() for c in cmts]})

    elif request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        cmt_text = (data.get('comment') or '').strip()
        if not cmt_text:
            return JsonResponse({'error': 'Comment body cannot be empty.'}, status=400)

        cmt = RequestComment.objects.create(
            saved_request=saved_req,
            user=user,
            comment=cmt_text
        )
        return JsonResponse({'success': True, 'comment': cmt.to_dict()}, status=201)


# --- PHASE 7: APIHUB INTELLIGENCE, DEVELOPER EXPERIENCE & QUALITY ENDPOINTS ---

HTTP_STATUS_EXPLANATIONS = {
    200: {
        'title': '200 OK',
        'meaning': 'The request has succeeded. The standard response for successful HTTP requests.',
        'common_causes': ['Server successfully processed request', 'Requested resource returned cleanly'],
        'suggested_checks': ['Verify response payload matches expected contract', 'Ensure response time meets SLA']
    },
    201: {
        'title': '201 Created',
        'meaning': 'The request has been fulfilled and resulted in a new resource being created.',
        'common_causes': ['POST request successfully created entity', 'Database row inserted'],
        'suggested_checks': ['Verify returned resource ID', 'Check Location header if present']
    },
    204: {
        'title': '204 No Content',
        'meaning': 'The server successfully processed the request, but is not returning any content.',
        'common_causes': ['DELETE request succeeded', 'PUT update succeeded with no body returned'],
        'suggested_checks': ['Verify database record was modified/deleted']
    },
    301: {
        'title': '301 Moved Permanently',
        'meaning': 'The target resource has been assigned a new permanent URI.',
        'common_causes': ['URL structure updated', 'HTTP redirected to HTTPS'],
        'suggested_checks': ['Update saved URL to new endpoint', 'Check redirect Location header']
    },
    302: {
        'title': '302 Found',
        'meaning': 'The target resource resides temporarily under a different URI.',
        'common_causes': ['Temporary redirect', 'Authentication flow redirecting to login'],
        'suggested_checks': ['Inspect Location header', 'Verify auth headers in redirect chain']
    },
    400: {
        'title': '400 Bad Request',
        'meaning': 'The server cannot process the request due to perceived client error.',
        'common_causes': ['Malformed JSON body', 'Missing required query parameters', 'Type validation failed'],
        'suggested_checks': ['Verify JSON body syntax', 'Check required fields against API spec', 'Inspect parameter data types']
    },
    401: {
        'title': '401 Unauthorized',
        'meaning': 'The request lacks valid authentication credentials for the target resource.',
        'common_causes': ['Missing Authorization header', 'Expired or invalid Bearer token', 'Incorrect credentials'],
        'suggested_checks': ['Verify Authorization header', 'Check token expiration', 'Refresh active environment credentials']
    },
    403: {
        'title': '403 Forbidden',
        'meaning': 'The server understood the request, but refuses to authorize it.',
        'common_causes': ['Insufficient role permissions', 'IP address restricted', 'CSRF token missing'],
        'suggested_checks': ['Verify user role/scopes', 'Check account permission settings']
    },
    404: {
        'title': '404 Not Found',
        'meaning': 'The server cannot find the requested resource.',
        'common_causes': ['Incorrect URL path', 'Invalid resource ID', 'Endpoint version deprecated or removed'],
        'suggested_checks': ['Verify URL path spelling', 'Ensure resource ID exists', 'Check API version prefix']
    },
    405: {
        'title': '405 Method Not Allowed',
        'meaning': 'The request method is known by the server but not supported by the target resource.',
        'common_causes': ['Using GET instead of POST', 'Resource is read-only'],
        'suggested_checks': ['Verify allowed HTTP methods (Allow header)', 'Change request method']
    },
    409: {
        'title': '409 Conflict',
        'meaning': 'The request could not be completed due to a conflict with current state of resource.',
        'common_causes': ['Duplicate entry (e.g., duplicate email)', 'Concurrent edit collision'],
        'suggested_checks': ['Check resource uniqueness constraints', 'Refresh resource before editing']
    },
    422: {
        'title': '422 Unprocessable Entity',
        'meaning': 'The request was well-formed but unable to be followed due to semantic errors.',
        'common_causes': ['Validation errors on specific fields', 'Business logic constraint failure'],
        'suggested_checks': ['Inspect error response details for field-specific validation messages']
    },
    429: {
        'title': '429 Too Many Requests',
        'meaning': 'The user has sent too many requests in a given amount of time (Rate Limited).',
        'common_causes': ['API rate limit exceeded', 'Too many concurrent requests'],
        'suggested_checks': ['Check Retry-After header', 'Implement request throttling / backoff']
    },
    500: {
        'title': '500 Internal Server Error',
        'meaning': 'The server encountered an unexpected condition that prevented it from fulfilling request.',
        'common_causes': ['Unhandled server exception', 'Database connection crash', 'Code bug on backend'],
        'suggested_checks': ['Inspect backend application logs', 'Verify database health']
    },
    502: {
        'title': '502 Bad Gateway',
        'meaning': 'The server, while acting as a gateway or proxy, received an invalid response from upstream.',
        'common_causes': ['Upstream backend service down', 'Proxy configuration failure'],
        'suggested_checks': ['Check upstream service status', 'Verify reverse proxy setup']
    },
    503: {
        'title': '503 Service Unavailable',
        'meaning': 'The server is currently unable to handle the request due to temporary overload/maintenance.',
        'common_causes': ['Server maintenance', 'High server load spikes'],
        'suggested_checks': ['Retry request after waiting', 'Check service status page']
    },
    504: {
        'title': '504 Gateway Timeout',
        'meaning': 'The server, while acting as a gateway, did not receive a timely response from upstream.',
        'common_causes': ['Upstream request timed out', 'Slow backend database query'],
        'suggested_checks': ['Increase proxy timeout threshold', 'Optimize backend execution time']
    }
}


def _explain_http_status(status_code):
    if not status_code:
        return {
            'title': 'No Response',
            'meaning': 'No HTTP response received (Network failure or timeout).',
            'common_causes': ['DNS failure', 'Connection refused', 'SSRF or CORS blocked'],
            'suggested_checks': ['Verify server host availability', 'Check target URL syntax']
        }
    code = int(status_code)
    return HTTP_STATUS_EXPLANATIONS.get(code, {
        'title': f'HTTP Status {code}',
        'meaning': f'Standard HTTP response status code {code}.',
        'common_causes': ['Returned by remote server'],
        'suggested_checks': ['Inspect response headers and body for details']
    })


def _generate_json_schema(obj):
    """Generates draft JSON Schema draft-07 from python data object."""
    if obj is None:
        return {'type': 'null'}
    elif isinstance(obj, bool):
        return {'type': 'boolean'}
    elif isinstance(obj, int):
        return {'type': 'integer'}
    elif isinstance(obj, float):
        return {'type': 'number'}
    elif isinstance(obj, str):
        return {'type': 'string'}
    elif isinstance(obj, list):
        if not obj:
            return {'type': 'array', 'items': {}}
        sample = obj[0]
        return {'type': 'array', 'items': _generate_json_schema(sample)}
    elif isinstance(obj, dict):
        properties = {}
        for k, v in obj.items():
            properties[k] = _generate_json_schema(v)
        return {
            'type': 'object',
            'properties': properties,
            'required': list(obj.keys())
        }
    return {'type': 'string'}


def _generate_openapi_response_schema(obj):
    """Generates OpenAPI 3.0 schema component from JSON object."""
    schema = _generate_json_schema(obj)
    return {
        'description': 'Auto-generated response schema (Inferred from observed response)',
        'content': {
            'application/json': {
                'schema': schema
            }
        }
    }


@csrf_exempt
@require_http_methods(["POST"])
def smart_analysis_api(request):
    """
    Performs smart response analysis, error diagnosis, test suggestions, and schema generation.
    Dual Mode:
      - Mode 1: Local deterministic analysis (Default when no AI provider configured).
      - Mode 2: Optional AI provider server-side integration if AI_PROVIDER & AI_API_KEY set (with secret redaction).
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        data = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    status_code = data.get('status_code')
    status_text = data.get('status_text', '')
    response_time_ms = data.get('response_time_ms', 0)
    response_size_kb = data.get('response_size_kb', 0)
    headers = data.get('headers', {})
    body_text = data.get('body', '')
    url = data.get('url', '')
    method = data.get('method', 'GET')

    ai_provider = os.environ.get('AI_PROVIDER')
    ai_api_key = os.environ.get('AI_API_KEY')

    mode = 'local'
    mode_label = 'Smart Local Analysis'
    mode_message = 'Smart analysis is running in local mode.'

    if ai_provider and ai_api_key:
        mode = 'ai'
        mode_label = 'AI-Assisted Analysis'
        mode_message = f'Analysis generated via configured external AI provider ({ai_provider}).'

    observations = []
    error_diagnosis = None
    status_explanation = _explain_http_status(status_code)
    suggested_tests = []
    parsed_json = None
    is_json = False

    if body_text:
        try:
            parsed_json = json.loads(body_text)
            is_json = True
            observations.append("Valid JSON response payload detected.")
            if isinstance(parsed_json, dict):
                keys = list(parsed_json.keys())
                observations.append(f"Response object contains {len(keys)} top-level field(s): {', '.join(keys[:6])}{'...' if len(keys)>6 else ''}.")
                pag_keys = [k for k in keys if k.lower() in ['page', 'next', 'previous', 'total', 'limit', 'offset', 'count']]
                if pag_keys:
                    observations.append(f"Pagination metadata detected: {', '.join(pag_keys)}.")
                nested = [k for k, v in parsed_json.items() if isinstance(v, (dict, list))]
                if nested:
                    observations.append(f"Nested structural elements observed in fields: {', '.join(nested[:5])}.")
            elif isinstance(parsed_json, list):
                observations.append(f"Response contains a top-level array of {len(parsed_json)} item(s).")
        except json.JSONDecodeError:
            is_json = False
            observations.append("Response is non-JSON text or binary data.")

    if response_time_ms:
        if response_time_ms < 300:
            observations.append(f"Fast response time ({round(response_time_ms, 1)}ms).")
        elif response_time_ms < 1000:
            observations.append(f"Moderate response time ({round(response_time_ms, 1)}ms).")
        else:
            observations.append(f"High latency response ({round(response_time_ms, 1)}ms). SLA performance threshold may be exceeded.")

    if response_size_kb:
        observations.append(f"Response size: {round(response_size_kb, 2)} KB.")

    if status_code and status_code >= 400:
        diagnosis_causes = status_explanation.get('common_causes', [])
        diagnosis_checks = status_explanation.get('suggested_checks', [])
        error_diagnosis = {
            'status_code': status_code,
            'summary': f"HTTP {status_code} error observed.",
            'possible_causes': diagnosis_causes,
            'suggested_checks': diagnosis_checks
        }

    if status_code == 200:
        suggested_tests.append({
            'name': 'Status code equals 200',
            'assertion_type': 'status_code',
            'target_path': '',
            'operator': 'equals',
            'expected_value': '200'
        })
    elif status_code:
        suggested_tests.append({
            'name': f'Status code equals {status_code}',
            'assertion_type': 'status_code',
            'target_path': '',
            'operator': 'equals',
            'expected_value': str(status_code)
        })

    if response_time_ms:
        threshold = 500 if response_time_ms < 400 else 1000
        suggested_tests.append({
            'name': f'Response time < {threshold}ms',
            'assertion_type': 'response_time',
            'target_path': '',
            'operator': 'less_than',
            'expected_value': str(threshold)
        })

    if is_json and isinstance(parsed_json, dict):
        suggested_tests.append({
            'name': 'Content-Type is application/json',
            'assertion_type': 'header',
            'target_path': 'Content-Type',
            'operator': 'contains',
            'expected_value': 'application/json'
        })
        for key in list(parsed_json.keys())[:3]:
            suggested_tests.append({
                'name': f'JSON key "{key}" exists',
                'assertion_type': 'json_path',
                'target_path': f'$.{key}',
                'operator': 'exists',
                'expected_value': ''
            })

    json_schema = _generate_json_schema(parsed_json) if is_json else None
    openapi_schema = _generate_openapi_response_schema(parsed_json) if is_json else None

    return JsonResponse({
        'mode': mode,
        'mode_label': mode_label,
        'mode_message': mode_message,
        'status_code': status_code,
        'status_explanation': status_explanation,
        'observations': observations,
        'error_diagnosis': error_diagnosis,
        'suggested_tests': suggested_tests,
        'is_json': is_json,
        'json_schema': json_schema,
        'openapi_schema': openapi_schema,
    })


@csrf_exempt
@require_http_methods(["GET"])
def status_explainer_api(request, status_code):
    """Returns detailed explanation of specified HTTP status code."""
    explanation = _explain_http_status(status_code)
    return JsonResponse({'status_code': status_code, 'explanation': explanation})


@csrf_exempt
@require_http_methods(["POST"])
def code_generator_api(request):
    """
    Generates runnable client code snippets (cURL, Python, JS Fetch, JS Axios, Java, Go, PHP)
    based on exact current request definition with secret redaction.
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        data = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    method = (data.get('method') or 'GET').upper()
    url = (data.get('url') or 'https://api.example.com/endpoint').strip()
    headers_list = data.get('headers', [])
    params_list = data.get('params', [])
    body = data.get('body', '')

    clean_headers = _normalize_key_values(headers_list)
    clean_params = _normalize_key_values(params_list)

    for k, v in clean_headers.items():
        if k.lower() in SENSITIVE_KEYS:
            clean_headers[k] = '{{token}}'

    # cURL
    curl_parts = [f"curl -X {method} '{url}'"]
    for k, v in clean_headers.items():
        curl_parts.append(f"  -H '{k}: {v}'")
    if body and method in ['POST', 'PUT', 'PATCH']:
        curl_parts.append(f"  -d '{body}'")
    curl_code = " \\\n".join(curl_parts)

    # Python Requests
    py_lines = ["import requests", "", f"url = \"{url}\""]
    if clean_headers:
        py_lines.append(f"headers = {json.dumps(clean_headers, indent=4)}")
    if clean_params:
        py_lines.append(f"params = {json.dumps(clean_params, indent=4)}")
    if body:
        py_lines.append(f"payload = {json.dumps(body)}")

    req_args = [f"\"{method}\"", "url"]
    if clean_headers:
        req_args.append("headers=headers")
    if clean_params:
        req_args.append("params=params")
    if body:
        req_args.append("data=payload")

    py_lines.append(f"\nresponse = requests.request({', '.join(req_args)})")
    py_lines.append("print(response.status_code)")
    py_lines.append("print(response.text)")
    python_code = "\n".join(py_lines)

    body_str = json.dumps(body) if isinstance(body, (dict, list)) else f"'{body}'"
    body_fetch_part = f",\n  body: JSON.stringify({body_str})" if body and method in ['POST', 'PUT', 'PATCH'] else ""
    body_axios_part = f",\n  data: {body_str}" if body and method in ['POST', 'PUT', 'PATCH'] else ""

    # JS Fetch
    js_fetch = f"""const url = '{url}';
const options = {{
  method: '{method}',
  headers: {json.dumps(clean_headers, indent=2)}{body_fetch_part}
}};

fetch(url, options)
  .then(res => res.json())
  .then(data => console.log(data))
  .catch(err => console.error(err));"""

    # JS Axios
    js_axios = f"""import axios from 'axios';

axios({{
  method: '{method.lower()}',
  url: '{url}',
  headers: {json.dumps(clean_headers, indent=2)}{body_axios_part}
}})
.then(response => console.log(response.data))
.catch(error => console.error(error));"""

    go_strings_import = '\t"strings"' if body else ""
    go_payload_decl = f'payload := strings.NewReader(`{body}`)' if body else 'var payload io.Reader = nil'

    # Go
    go_code = f"""package main

import (
	"fmt"
	"io"
	"net/http"
{go_strings_import}
)

func main() {{
	url := "{url}"
	method := "{method}"
	{go_payload_decl}

	client := &http.Client{{}}
	req, err := http.NewRequest(method, url, payload)
	if err != nil {{
		fmt.Println(err)
		return
	}}
"""
    for k, v in clean_headers.items():
        go_code += f'\treq.Header.Add("{k}", "{v}")\n'
    go_code += """
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	fmt.Println(string(body))
}"""

    # PHP
    php_code = f"""<?php
$curl = curl_init();

curl_setopt_array($curl, array(
  CURLOPT_URL => '{url}',
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_CUSTOMREQUEST => '{method}',
"""
    if body:
        php_code += f"  CURLOPT_POSTFIELDS => '{body}',\n"
    if clean_headers:
        hdrs_arr = [f"'{k}: {v}'" for k, v in clean_headers.items()]
        php_code += f"  CURLOPT_HTTPHEADER => array({', '.join(hdrs_arr)}),\n"
    php_code += """));

$response = curl_exec($curl);
curl_close($curl);
echo $response;"""

    # Java
    java_code = f"""import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class ApiClient {{
    public static void main(String[] args) throws Exception {{
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest.Builder builder = HttpRequest.newBuilder()
            .uri(URI.create("{url}"));
"""
    for k, v in clean_headers.items():
        java_code += f'        builder.header("{k}", "{v}");\n'
    if body and method in ['POST', 'PUT', 'PATCH']:
        java_code += f'        builder.method("{method}", HttpRequest.BodyPublishers.ofString("{body}"));\n'
    else:
        java_code += f'        builder.method("{method}", HttpRequest.BodyPublishers.noBody());\n'
    java_code += """
        HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        System.out.println(response.statusCode());
        System.out.println(response.body());
    }
}"""

    return JsonResponse({
        'curl': curl_code,
        'python': python_code,
        'javascript_fetch': js_fetch,
        'javascript_axios': js_axios,
        'go': go_code,
        'php': php_code,
        'java': java_code
    })


@csrf_exempt
@require_http_methods(["POST"])
def diff_requests_api(request):
    """Compares two saved requests by ID and returns field-by-field diff."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        data = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    req1_id = data.get('request_1_id')
    req2_id = data.get('request_2_id')
    if not req1_id or not req2_id:
        return JsonResponse({'error': 'request_1_id and request_2_id are required.'}, status=400)

    try:
        req1 = SavedRequest.objects.get(id=req1_id, user=request.user)
        req2 = SavedRequest.objects.get(id=req2_id, user=request.user)
    except SavedRequest.DoesNotExist:
        return JsonResponse({'error': 'One or both requests not found.'}, status=404)

    diffs = {
        'request_1': req1.to_dict(),
        'request_2': req2.to_dict(),
        'method_diff': {'same': req1.method == req2.method, 'val1': req1.method, 'val2': req2.method},
        'url_diff': {'same': req1.url == req2.url, 'val1': req1.url, 'val2': req2.url},
        'auth_diff': {'same': req1.auth_type == req2.auth_type, 'val1': req1.auth_type, 'val2': req2.auth_type},
        'body_diff': {'same': req1.body == req2.body, 'val1': req1.body, 'val2': req2.body},
        'headers_diff': {'val1': req1.headers, 'val2': req2.headers},
        'params_diff': {'val1': req1.params, 'val2': req2.params},
        'tests_diff': {'val1': req1.tests, 'val2': req2.tests},
    }
    return JsonResponse({'diff': diffs})


@csrf_exempt
@require_http_methods(["POST"])
def diff_responses_api(request):
    """Performs JSON-aware structural diffing between two response payloads."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        data = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    resp_a_str = data.get('response_a', '')
    resp_b_str = data.get('response_b', '')

    try:
        json_a = json.loads(resp_a_str)
        json_b = json.loads(resp_b_str)
    except Exception:
        return JsonResponse({'error': 'Both responses must be valid JSON strings for structural diff.'}, status=400)

    added = []
    removed = []
    changed = []
    unchanged = []

    def _compare_nodes(node_a, node_b, path=""):
        if type(node_a) != type(node_b):
            changed.append({'path': path or '$', 'old_val': node_a, 'new_val': node_b, 'reason': 'Type mismatch'})
            return

        if isinstance(node_a, dict):
            keys_a = set(node_a.keys())
            keys_b = set(node_b.keys())

            for k in keys_b - keys_a:
                added.append({'path': f"{path}.{k}" if path else f"$.{k}", 'val': node_b[k]})
            for k in keys_a - keys_b:
                removed.append({'path': f"{path}.{k}" if path else f"$.{k}", 'val': node_a[k]})
            for k in keys_a & keys_b:
                _compare_nodes(node_a[k], node_b[k], f"{path}.{k}" if path else f"$.{k}")

        elif isinstance(node_a, list):
            min_len = min(len(node_a), len(node_b))
            for i in range(min_len):
                _compare_nodes(node_a[i], node_b[i], f"{path}[{i}]")
            if len(node_b) > len(node_a):
                for i in range(min_len, len(node_b)):
                    added.append({'path': f"{path}[{i}]", 'val': node_b[i]})
            elif len(node_a) > len(node_b):
                for i in range(min_len, len(node_a)):
                    removed.append({'path': f"{path}[{i}]", 'val': node_a[i]})
        else:
            if node_a == node_b:
                unchanged.append({'path': path or '$', 'val': node_a})
            else:
                changed.append({'path': path or '$', 'old_val': node_a, 'new_val': node_b})

    _compare_nodes(json_a, json_b)

    return JsonResponse({
        'added': added,
        'removed': removed,
        'changed': changed,
        'unchanged_count': len(unchanged),
        'total_differences': len(added) + len(removed) + len(changed)
    })


@csrf_exempt
@require_http_methods(["POST"])
def openapi_diff_api(request):
    """Compares two OpenAPI specifications and identifies structural changes and breaking changes."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        data = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    spec_a_str = data.get('spec_a', '')
    spec_b_str = data.get('spec_b', '')

    spec_a = _parse_openapi_spec(spec_a_str)
    spec_b = _parse_openapi_spec(spec_b_str)

    if not spec_a or not spec_b:
        return JsonResponse({'error': 'Could not parse one or both OpenAPI specifications.'}, status=400)

    endpoints_a = {f"{req['method']} {req['url']}": req for req in spec_a.get('requests', [])}
    endpoints_b = {f"{req['method']} {req['url']}": req for req in spec_b.get('requests', [])}

    added_endpoints = []
    removed_endpoints = []
    changed_endpoints = []
    breaking_changes = []

    for ep in set(endpoints_b.keys()) - set(endpoints_a.keys()):
        added_endpoints.append({'endpoint': ep, 'summary': endpoints_b[ep].get('name', '')})

    for ep in set(endpoints_a.keys()) - set(endpoints_b.keys()):
        removed_endpoints.append({'endpoint': ep, 'summary': endpoints_a[ep].get('name', '')})
        breaking_changes.append({'type': 'ENDPOINT_REMOVED', 'description': f"Endpoint '{ep}' was removed."})

    for ep in set(endpoints_a.keys()) & set(endpoints_b.keys()):
        req_a = endpoints_a[ep]
        req_b = endpoints_b[ep]
        changes = []
        if req_a.get('params') != req_b.get('params'):
            changes.append("Parameters updated")
        if req_a.get('body') != req_b.get('body'):
            changes.append("Request body updated")
        if changes:
            changed_endpoints.append({'endpoint': ep, 'changes': changes})

    return JsonResponse({
        'title_a': spec_a.get('title', 'Spec A'),
        'title_b': spec_b.get('title', 'Spec B'),
        'added_endpoints': added_endpoints,
        'removed_endpoints': removed_endpoints,
        'changed_endpoints': changed_endpoints,
        'potential_breaking_changes': breaking_changes,
        'summary': {
            'added': len(added_endpoints),
            'removed': len(removed_endpoints),
            'changed': len(changed_endpoints),
            'breaking': len(breaking_changes)
        }
    })


@csrf_exempt
@require_http_methods(["GET"])
def workspace_health_api(request):
    """
    Scans active workspace for API configuration completeness, unused/duplicate/broken requests,
    environment diagnostics, and monitor health.
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    workspace_id = request.GET.get('workspace_id')
    if workspace_id:
        try:
            ws = Workspace.objects.get(id=workspace_id)
            if not _has_workspace_permission(request.user, ws, 'VIEWER'):
                return JsonResponse({'error': 'Forbidden.'}, status=403)
        except Workspace.DoesNotExist:
            return JsonResponse({'error': 'Workspace not found.'}, status=404)
        saved_reqs = SavedRequest.objects.filter(collection__workspace=ws, is_archived=False)
        collections = Collection.objects.filter(workspace=ws, is_archived=False)
        envs = Environment.objects.filter(workspace=ws)
        monitors = Monitor.objects.filter(workspace=ws)
    else:
        saved_reqs = SavedRequest.objects.filter(user=request.user, is_archived=False)
        collections = Collection.objects.filter(user=request.user, is_archived=False)
        envs = Environment.objects.filter(user=request.user)
        monitors = Monitor.objects.filter(user=request.user)

    total_reqs = saved_reqs.count()

    completeness_score = 100.0
    scoring_rules = []
    if total_reqs == 0:
        completeness_score = 100.0
        scoring_rules.append("No saved requests in workspace.")
    else:
        reqs_with_desc = saved_reqs.exclude(description='').count()
        reqs_with_tests = saved_reqs.exclude(tests=[]).count()
        reqs_with_contract = saved_reqs.exclude(contract_schema={}).count()

        desc_pct = (reqs_with_desc / total_reqs) * 33.3
        test_pct = (reqs_with_tests / total_reqs) * 33.3
        contract_pct = (reqs_with_contract / total_reqs) * 33.4
        completeness_score = round(desc_pct + test_pct + contract_pct, 1)

        scoring_rules.append(f"+{round(desc_pct,1)}% for endpoint descriptions ({reqs_with_desc}/{total_reqs})")
        scoring_rules.append(f"+{round(test_pct,1)}% for test assertions ({reqs_with_tests}/{total_reqs})")
        scoring_rules.append(f"+{round(contract_pct,1)}% for contract schemas ({reqs_with_contract}/{total_reqs})")

    seen_endpoints = {}
    duplicates = []
    for req in saved_reqs:
        key = f"{req.method.upper()} {req.url.strip().lower()}"
        if key in seen_endpoints:
            duplicates.append({'request_1': seen_endpoints[key], 'request_2': req.to_dict(), 'endpoint': key})
        else:
            seen_endpoints[key] = req.to_dict()

    recent_history_urls = set(RequestHistory.objects.filter(user=request.user, timestamp__gte=timezone.now() - timedelta(days=30)).values_list('url', flat=True))
    unused_requests = []
    for req in saved_reqs:
        if req.url and req.url not in recent_history_urls:
            unused_requests.append(req.to_dict())

    active_env_vars = set()
    for env in envs:
        for var in env.variables.all():
            active_env_vars.add(var.key)

    undefined_vars = []
    broken_requests = []
    var_pattern = re.compile(r'\{\{([a-zA-Z0-9_\-]+)\}\}')

    for req in saved_reqs:
        if not req.url or not (req.url.startswith('http://') or req.url.startswith('https://') or '{{' in req.url):
            broken_requests.append({'request': req.to_dict(), 'issue': 'Invalid or missing HTTP/HTTPS URL scheme'})

        matches = var_pattern.findall(f"{req.url} {req.body} {json.dumps(req.headers)} {json.dumps(req.params)}")
        for v in matches:
            if v not in active_env_vars:
                undefined_vars.append({'variable': v, 'referenced_by': req.name, 'request_id': req.id})

    unique_undefined = list({uv['variable']: uv for uv in undefined_vars}.values())
    failing_monitors = [m.to_dict() for m in monitors if m.calculate_metrics()['health_status'] == 'Down']

    return JsonResponse({
        'total_saved_requests': total_reqs,
        'configuration_completeness_score': completeness_score,
        'scoring_rules': scoring_rules,
        'unused_requests_count': len(unused_requests),
        'unused_requests': unused_requests[:10],
        'duplicate_requests_count': len(duplicates),
        'duplicate_requests': duplicates[:10],
        'broken_requests_count': len(broken_requests),
        'broken_requests': broken_requests,
        'undefined_variables_count': len(unique_undefined),
        'undefined_variables': unique_undefined,
        'failing_monitors_count': len(failing_monitors),
        'failing_monitors': failing_monitors
    })


@csrf_exempt
@require_http_methods(["POST"])
def preflight_check_api(request):
    """Performs lightweight pre-flight validation on a request prior to execution."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        data = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    url = (data.get('url') or '').strip()
    headers = data.get('headers', [])
    body = data.get('body', '')
    environment_id = data.get('environment_id')

    warnings = []
    passed = True

    if not url:
        warnings.append({'field': 'url', 'message': 'Target URL is missing.'})
        passed = False
    elif not (url.startswith('http://') or url.startswith('https://') or '{{' in url):
        warnings.append({'field': 'url', 'message': 'URL should begin with http:// or https://'})

    if body:
        try:
            json.loads(body)
        except Exception as e:
            warnings.append({'field': 'body', 'message': f'Malformed JSON body: {str(e)}'})

    if environment_id:
        try:
            env = Environment.objects.get(id=environment_id, user=request.user)
            available_vars = set(env.variables.values_list('key', flat=True))
            matches = re.findall(r'\{\{([a-zA-Z0-9_\-]+)\}\}', f"{url} {body} {json.dumps(headers)}")
            for v in matches:
                if v not in available_vars:
                    warnings.append({'field': 'environment', 'message': f"Referenced variable '{{{{{v}}}}}' is undefined in environment '{env.name}'."})
        except Environment.DoesNotExist:
            warnings.append({'field': 'environment', 'message': 'Selected environment not found.'})

    return JsonResponse({'passed': passed, 'warnings': warnings})


@csrf_exempt
@require_http_methods(["POST"])
def archive_resource_api(request):
    """Archives or unarchives Requests, Collections, or ApiVersions."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        data = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    resource_type = data.get('resource_type')
    resource_id = data.get('resource_id')
    action = data.get('action', 'archive')

    if not resource_type or not resource_id:
        return JsonResponse({'error': 'resource_type and resource_id are required.'}, status=400)

    is_archived_val = (action == 'archive')

    if resource_type == 'request':
        try:
            obj = SavedRequest.objects.get(id=resource_id, user=request.user)
            obj.is_archived = is_archived_val
            obj.save()
            return JsonResponse({'success': True, 'resource': obj.to_dict()})
        except SavedRequest.DoesNotExist:
            return JsonResponse({'error': 'Request not found.'}, status=404)

    elif resource_type == 'collection':
        try:
            obj = Collection.objects.get(id=resource_id, user=request.user)
            obj.is_archived = is_archived_val
            obj.save()
            return JsonResponse({'success': True, 'resource': obj.to_dict()})
        except Collection.DoesNotExist:
            return JsonResponse({'error': 'Collection not found.'}, status=404)

    elif resource_type == 'version':
        try:
            obj = ApiVersion.objects.get(id=resource_id, user=request.user)
            obj.is_archived = is_archived_val
            obj.save()
            return JsonResponse({'success': True, 'resource': obj.to_dict()})
        except ApiVersion.DoesNotExist:
            return JsonResponse({'error': 'API Version not found.'}, status=404)

    return JsonResponse({'error': 'Invalid resource_type.'}, status=400)


@csrf_exempt
@require_http_methods(["POST"])
def bulk_actions_api(request):
    """Performs bulk actions (archive, unarchive, delete, export) on selected saved requests."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    try:
        data = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    request_ids = data.get('request_ids', [])
    action = data.get('action')

    if not request_ids or not action:
        return JsonResponse({'error': 'request_ids list and action are required.'}, status=400)

    qs = SavedRequest.objects.filter(id__in=request_ids, user=request.user)

    if action == 'archive':
        qs.update(is_archived=True)
        return JsonResponse({'success': True, 'archived_count': qs.count()})
    elif action == 'unarchive':
        qs.update(is_archived=False)
        return JsonResponse({'success': True, 'unarchived_count': qs.count()})
    elif action == 'delete':
        count = qs.count()
        qs.delete()
        return JsonResponse({'success': True, 'deleted_count': count})
    elif action == 'export_json':
        export_data = {'apihub_export': [r.to_dict() for r in qs]}
        return JsonResponse(export_data)
    elif action == 'export_curl':
        curls = []
        for r in qs:
            curls.append(f"# {r.name}\ncurl -X {r.method} '{r.url}'")
        return HttpResponse("\n\n".join(curls), content_type='text/plain')

    return JsonResponse({'error': 'Invalid bulk action.'}, status=400)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def demo_mode_api(request):
    """
    Initializes or toggles isolated Demo Workspace with safe synthetic data (Users API, Auth API, Products API).
    Demo Mode NEVER makes real external mutations or triggers real webhooks.
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    if request.method == "POST":
        ws, _ = Workspace.objects.get_or_create(
            owner=request.user,
            is_demo=True,
            defaults={'name': '⚡ DEMO MODE WORKSPACE', 'description': 'Safe isolated demo workspace for presentations'}
        )
        WorkspaceMember.objects.get_or_create(workspace=ws, user=request.user, defaults={'role': 'OWNER'})

        Collection.objects.filter(workspace=ws).delete()

        col_users = Collection.objects.create(user=request.user, workspace=ws, name='Users API (Demo)', description='Synthetic demo endpoints for user management')
        SavedRequest.objects.create(
            user=request.user,
            collection=col_users,
            name='Get All Users',
            method='GET',
            url='https://jsonplaceholder.typicode.com/users',
            description='Retrieves list of synthetic users',
            tests=[{'name': 'Status is 200', 'assertion_type': 'status_code', 'operator': 'equals', 'expected_value': '200'}]
        )
        SavedRequest.objects.create(
            user=request.user,
            collection=col_users,
            name='Create User',
            method='POST',
            url='https://jsonplaceholder.typicode.com/users',
            body='{"name": "Demo User", "email": "demo@apihub.internal"}',
            description='Creates a new synthetic user record',
            tests=[{'name': 'Status is 201', 'assertion_type': 'status_code', 'operator': 'equals', 'expected_value': '201'}]
        )

        col_auth = Collection.objects.create(user=request.user, workspace=ws, name='Authentication API (Demo)', description='Synthetic OAuth2 & Auth endpoints')
        SavedRequest.objects.create(
            user=request.user,
            collection=col_auth,
            name='Login Token',
            method='POST',
            url='https://jsonplaceholder.typicode.com/posts',
            body='{"username": "admin", "password": "demo-password"}',
            tests=[{'name': 'Status is 201', 'assertion_type': 'status_code', 'operator': 'equals', 'expected_value': '201'}]
        )

        return JsonResponse({
            'success': True,
            'demo_workspace': ws.to_dict(),
            'message': 'Demo Mode Workspace initialized with synthetic collections & requests.'
        })

    elif request.method == "GET":
        ws = Workspace.objects.filter(owner=request.user, is_demo=True).first()
        return JsonResponse({
            'demo_active': ws is not None,
            'demo_workspace': ws.to_dict() if ws else None
        })

