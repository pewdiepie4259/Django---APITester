import json
import time
from urllib.parse import urlparse
import requests
from requests.auth import HTTPBasicAuth

from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import RequestHistory


def index(request):
    """Render the APIHub single-page application interface."""
    recent_history = RequestHistory.objects.all()[:30]
    return render(request, 'client/index.html', {'recent_history': recent_history})


def _normalize_key_values(items):
    """
    Accepts either:
    - dict: {"key": "val"}
    - list of dicts: [{"key": "k", "value": "v", "enabled": True}]
    Returns a clean dict.
    """
    if isinstance(items, dict):
        return items
    if isinstance(items, list):
        result = {}
        for item in items:
            if isinstance(item, dict):
                # if 'enabled' key exists and is False, skip
                if item.get('enabled') is False:
                    continue
                k = item.get('key', '').strip()
                v = item.get('value', '')
                if k:
                    result[k] = v
        return result
    return {}


@csrf_exempt
@require_http_methods(["POST"])
def execute_request(request):
    """
    Executes outbound HTTP request proxying on behalf of the user.
    Bypasses CORS restrictions and records request metrics.
    """
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON request body.'}, status=400)

    method = (payload.get('method') or 'GET').strip().upper()
    url = (payload.get('url') or '').strip()

    if not url:
        return JsonResponse({'error': 'URL is required.'}, status=400)

    # Prepend http:// if protocol is missing
    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'https://' + url

    headers_raw = payload.get('headers', {})
    params_raw = payload.get('params', {})
    auth_data = payload.get('auth', {})
    body_data = payload.get('body', '')

    clean_headers = _normalize_key_values(headers_raw)
    clean_params = _normalize_key_values(params_raw)

    # Process Authorization
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

    # Process body
    send_data = None
    if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
        if isinstance(body_data, (dict, list)):
            send_data = json.dumps(body_data).encode('utf-8')
            if 'Content-Type' not in clean_headers and 'content-type' not in clean_headers:
                clean_headers['Content-Type'] = 'application/json'
        elif isinstance(body_data, str) and body_data:
            send_data = body_data.encode('utf-8')

    # Execute request
    start_time = time.perf_counter()
    status_code = None
    status_text = ''
    response_headers = {}
    response_data = None
    is_json = False
    size_kb = 0.0
    latency_ms = 0.0

    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=clean_headers,
            params=clean_params,
            data=send_data,
            auth=req_auth,
            timeout=15,
            allow_redirects=True,
        )
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = resp.status_code
        status_text = resp.reason or 'OK'
        response_headers = dict(resp.headers)
        size_kb = len(resp.content) / 1024.0

        try:
            response_data = resp.json()
            is_json = True
        except Exception:
            response_data = resp.text
            is_json = False

    except requests.exceptions.Timeout as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = 504
        status_text = 'Gateway Timeout (15s)'
        response_data = {'error': f'Request timed out after 15 seconds: {str(exc)}'}
        is_json = True
    except requests.exceptions.ConnectionError as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = 502
        status_text = 'Connection Error'
        response_data = {'error': f'Failed to establish connection: {str(exc)}'}
        is_json = True
    except requests.exceptions.RequestException as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = 500
        status_text = 'Request Failed'
        response_data = {'error': str(exc)}
        is_json = True
    except Exception as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = 500
        status_text = 'Internal Error'
        response_data = {'error': str(exc)}
        is_json = True

    # Persist in history
    try:
        body_to_store = body_data if isinstance(body_data, str) else json.dumps(body_data)
        history_entry = RequestHistory.objects.create(
            method=method,
            url=url,
            headers=clean_headers,
            params=clean_params,
            body=body_to_store,
            status_code=status_code,
            status_text=status_text,
            response_time_ms=latency_ms,
            response_size_kb=size_kb,
        )
        saved_id = history_entry.id
    except Exception as e:
        saved_id = None

    return JsonResponse({
        'status_code': status_code,
        'status_text': status_text,
        'time_ms': round(latency_ms, 2),
        'size_kb': round(size_kb, 2),
        'headers': response_headers,
        'data': response_data,
        'is_json': is_json,
        'history_id': saved_id,
    })


@csrf_exempt
@require_http_methods(["GET", "DELETE"])
def history_api(request):
    """
    GET: List recent request history.
    DELETE: Clear all or single history item.
    """
    if request.method == "GET":
        items = RequestHistory.objects.all()[:50]
        return JsonResponse({'history': [item.to_dict() for item in items]})

    elif request.method == "DELETE":
        item_id = request.GET.get('id')
        if item_id:
            RequestHistory.objects.filter(id=item_id).delete()
            return JsonResponse({'success': True, 'deleted_id': item_id})
        else:
            RequestHistory.objects.all().delete()
            return JsonResponse({'success': True, 'cleared_all': True})
