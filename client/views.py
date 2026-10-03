import json
import re
import time
import socket
import ipaddress
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
    ApiTest, TestRun, TestResult, AuditLog, UserSettings
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

    # Direct blocked hostnames
    blocked_hosts = {
        'localhost', '127.0.0.1', '::1', '0.0.0.0',
        '169.254.169.254', 'metadata.google.internal', 'instance-data', 'metadata'
    }
    if host in blocked_hosts:
        return False, f"Access to restricted host '{host}' is blocked for security."

    # Resolve IP address to prevent internal network scanning
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
        # If offline or DNS unresolvable, allow standard public FQDNs with dots
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
    """Handles User Authentication Login."""
    if request.user.is_authenticated:
        return redirect('client:index')

    if request.method == "POST":
        username_or_email = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        if not username_or_email or not password:
            return render(request, 'client/login.html', {'error': 'Username and password are required.'})

        # Allow authentication via username or email
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
    """Handles User Account Registration with Django Password Validation."""
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

        # Create User
        user = User.objects.create_user(username=username, email=email, password=password)
        UserSettings.objects.create(user=user)
        login(request, user)

        _log_audit(user, "REGISTER", "User", user.id)
        return redirect('client:index')

    return render(request, 'client/register.html')


def logout_view(request):
    """Logs out user and clears session."""
    if request.user.is_authenticated:
        _log_audit(request.user, "LOGOUT", "User", request.user.id)
        logout(request)
    return redirect('client:login')


@login_required(login_url='/login/')
def profile_view(request):
    """User Profile information display & updating."""
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
    """Workspace settings view."""
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
    """Export all user-owned workspace data in JSON format."""
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
        'history': [h.to_dict() for h in RequestHistory.objects.filter(user=user)[:100]],
    }
    _log_audit(user, "EXPORT_DATA", "User", user.id)
    response = JsonResponse(data, json_dumps_params={'indent': 2})
    response['Content-Disposition'] = f'attachment; filename="apihub_export_{user.username}.json"'
    return response


@login_required(login_url='/login/')
def delete_account(request):
    """Permanently deletes user account and cascades all owned data."""
    if request.method == "POST":
        user = request.user
        _log_audit(user, "DELETE_ACCOUNT", "User", user.id)
        user.delete()
        logout(request)
        return redirect('client:login')
    return redirect('client:settings')


# --- APPLICATION INDEX (SPA) ---
@login_required(login_url='/login/')
def index(request):
    """Render the main APIHub SPA interface for authenticated user."""
    recent_history = RequestHistory.objects.filter(user=request.user)[:30]
    audit_logs = AuditLog.objects.filter(user=request.user)[:10]
    user_settings, _ = UserSettings.objects.get_or_create(user=request.user)

    return render(request, 'client/index.html', {
        'user': request.user,
        'recent_history': recent_history,
        'audit_logs': audit_logs,
        'user_settings': user_settings,
    })


# --- API ENDPOINTS (AUTHENTICATED & USER SCOPED) ---

@csrf_exempt
@require_http_methods(["POST"])
def execute_request(request):
    """
    Executes outbound HTTP request proxying on behalf of authenticated user.
    Enforces SSRF filtering, variable substitution, size limits, secret redaction, and assertion evaluation.
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    # 1. Payload Body Size Check (10MB Limit)
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

    # Load User's Environment Variables for substitution
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

    # Variable Substitution
    url = _substitute_string(url, env_vars)
    headers_raw = _substitute_obj(payload.get('headers', {}), env_vars)
    params_raw = _substitute_obj(payload.get('params', {}), env_vars)
    auth_data = _substitute_obj(payload.get('auth', {}), env_vars)
    body_data = _substitute_obj(payload.get('body', ''), env_vars)

    # Prepend http:// if missing
    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'https://' + url

    # SSRF Security Validation
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

    # Get timeout preference
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

    # Evaluate Test Assertions if provided
    test_definitions = payload.get('tests', [])
    test_results, test_summary = _evaluate_assertions(
        test_definitions,
        {
            'status_code': status_code,
            'time_ms': latency_ms,
            'headers': response_headers,
            'body': raw_body_text,
            'data': response_data,
            'is_json': is_json,
        }
    )

    # Persist in history with REDACTED sensitive headers
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
        collections = Collection.objects.filter(user=request.user).prefetch_related('requests')
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
            description=data.get('description', '').strip()
        )
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
            tests=data.get('tests', [])
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
        tests=source_req.tests
    )
    _log_audit(request.user, "DUPLICATE_REQUEST", "SavedRequest", dup_req.id)
    return JsonResponse({'success': True, 'request': dup_req.to_dict()}, status=201)


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

        eval_results, eval_summary = _evaluate_assertions(
            req.tests,
            {
                'status_code': status_code,
                'time_ms': req_latency,
                'headers': response_headers,
                'body': raw_body_text,
                'data': response_data,
                'is_json': is_json,
            }
        )

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
        tests=data.get('tests', [])
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
