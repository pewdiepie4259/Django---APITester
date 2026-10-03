import json
import yaml
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from client.models import (
    RequestHistory, Collection, SavedRequest, Environment, EnvironmentVariable,
    AuditLog, UserSettings, ApiSpecification, ApiVersion, TestSuite, TestSuiteRun,
    Monitor, MonitorRun, AlertRule, Notification, MockEndpoint, PublicDocumentation,
    Workspace, WorkspaceMember, WorkspaceInvitation, PersonalAccessToken,
    Webhook, WebhookDelivery, CiRun, RequestComment
)
from client.views import _validate_api_contract, _parse_openapi_spec, _execute_monitor, _dispatch_workspace_webhooks


class APIHubTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='StrongPass#2026!')
        self.user2 = User.objects.create_user(username='otheruser', email='other@example.com', password='StrongPass#2026!')
        self.client.login(username='testuser', password='StrongPass#2026!')

    def test_health_and_ready_endpoints(self):
        health_resp = self.client.get(reverse('client:health'))
        self.assertEqual(health_resp.status_code, 200)
        self.assertEqual(health_resp.json()['status'], 'ok')

        ready_resp = self.client.get(reverse('client:ready'))
        self.assertEqual(ready_resp.status_code, 200)
        self.assertEqual(ready_resp.json()['status'], 'ready')

    def test_authentication_flow(self):
        self.client.logout()
        idx_resp = self.client.get(reverse('client:index'))
        self.assertEqual(idx_resp.status_code, 302)

        reg_resp = self.client.post(reverse('client:register'), {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'Complex#Pass9876!',
            'confirm_password': 'Complex#Pass9876!'
        })
        self.assertEqual(reg_resp.status_code, 302)
        self.assertTrue(User.objects.filter(username='newuser').exists())

        self.client.logout()
        login_resp = self.client.post(reverse('client:login'), {'username': 'testuser', 'password': 'StrongPass#2026!'})
        self.assertEqual(login_resp.status_code, 302)

    def test_user_data_isolation(self):
        col1 = Collection.objects.create(user=self.user, name='User 1 Collection')
        col2 = Collection.objects.create(user=self.user2, name='User 2 Collection')

        resp = self.client.get(reverse('client:collections_api'))
        self.assertEqual(resp.status_code, 200)
        cols = resp.json()['collections']
        self.assertEqual(len(cols), 1)
        self.assertEqual(cols[0]['name'], 'User 1 Collection')

        detail_resp = self.client.get(reverse('client:collection_detail_api', kwargs={'collection_id': col2.id}))
        self.assertEqual(detail_resp.status_code, 404)

        del_resp = self.client.delete(reverse('client:collection_detail_api', kwargs={'collection_id': col2.id}))
        self.assertEqual(del_resp.status_code, 404)
        self.assertTrue(Collection.objects.filter(id=col2.id).exists())

    @patch('client.views.requests.request')
    def test_execute_request_and_secret_redaction(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.reason = 'OK'
        mock_resp.headers = {'Content-Type': 'application/json'}
        mock_resp.content = b'{"userId": 1, "id": 1, "title": "Test Title"}'
        mock_resp.json.return_value = {"userId": 1, "id": 1, "title": "Test Title"}
        mock_resp.text = '{"userId": 1, "id": 1, "title": "Test Title"}'
        mock_request.return_value = mock_resp

        payload = {
            'method': 'GET',
            'url': 'https://jsonplaceholder.typicode.com/posts/1',
            'headers': [{'key': 'Authorization', 'value': 'Bearer secret-token-12345'}],
            'params': [],
            'auth': {'type': 'none'},
            'body': ''
        }

        response = self.client.post(
            reverse('client:execute_request'),
            data=json.dumps(payload),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(RequestHistory.objects.count(), 1)
        entry = RequestHistory.objects.first()
        self.assertEqual(entry.headers.get('Authorization'), '[REDACTED]')

    def test_ssrf_and_security_filtering(self):
        from client.views import _is_safe_url

        is_safe, msg = _is_safe_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(is_safe)
        self.assertIn("blocked", msg)

        is_safe_local, msg_local = _is_safe_url("http://127.0.0.1:8000/admin")
        self.assertFalse(is_safe_local)

        is_safe_ext, _ = _is_safe_url("https://api.example.com/data")
        self.assertTrue(is_safe_ext)

    # --- PHASE 5 TESTS ---

    def test_openapi_import_and_export(self):
        sample_openapi_yaml = """
openapi: 3.0.0
info:
  title: Users API Spec
  version: 2.1.0
  description: Test OpenAPI specification
servers:
  - url: https://api.example.com/v2
paths:
  /users:
    get:
      summary: List Users
      parameters:
        - name: limit
          in: query
          example: 10
      responses:
        '200':
          description: OK
"""
        # Test Import
        resp = self.client.post(
            reverse('client:import_openapi_api'),
            data=json.dumps({'spec': sample_openapi_yaml}),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['summary']['title'], 'Users API Spec')
        self.assertEqual(data['imported_requests'], 1)

        col_id = data['collection']['id']

        # Test Export JSON
        exp_json = self.client.get(reverse('client:export_openapi_api', kwargs={'collection_id': col_id}) + '?format=json')
        self.assertEqual(exp_json.status_code, 200)
        self.assertEqual(exp_json.json()['info']['title'], 'Users API Spec')

        # Test Export YAML
        exp_yaml = self.client.get(reverse('client:export_openapi_api', kwargs={'collection_id': col_id}) + '?format=yaml')
        self.assertEqual(exp_yaml.status_code, 200)
        self.assertIn('Users API Spec', exp_yaml.content.decode('utf-8'))

    def test_contract_testing_validation(self):
        contract_schema = {
            'expected_status': 200,
            'expected_content_type': 'application/json',
            'required_fields': ['id', 'email'],
            'field_types': {'id': 'integer', 'email': 'string'}
        }

        # 1. Valid Response
        valid_resp = {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json; charset=utf-8'},
            'data': {'id': 123, 'email': 'user@example.com'},
            'is_json': True
        }
        passed, checks = _validate_api_contract(contract_schema, valid_resp)
        self.assertTrue(passed)

        # 2. Invalid Field Type Violation
        invalid_resp = {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'data': {'id': "123", 'email': 'user@example.com'}, # id is string instead of integer
            'is_json': True
        }
        passed_inv, checks_inv = _validate_api_contract(contract_schema, invalid_resp)
        self.assertFalse(passed_inv)
        self.assertTrue(any("Contract Violation" in c['message'] for c in checks_inv))

    def test_reusable_test_suites(self):
        col = Collection.objects.create(user=self.user, name='Suite Collection')
        req1 = SavedRequest.objects.create(user=self.user, collection=col, name='Req 1', method='GET', url='https://jsonplaceholder.typicode.com/posts/1')
        req2 = SavedRequest.objects.create(user=self.user, collection=col, name='Req 2', method='GET', url='https://jsonplaceholder.typicode.com/posts/2')

        # Create Test Suite
        suite_resp = self.client.post(
            reverse('client:test_suites_api'),
            data=json.dumps({
                'name': 'Integration Suite',
                'description': 'Runs endpoints 1 and 2',
                'requests': [req1.id, req2.id]
            }),
            content_type='application/json'
        )
        self.assertEqual(suite_resp.status_code, 201)
        suite_id = suite_resp.json()['test_suite']['id']

        # Run Test Suite
        with patch('client.views.requests.request') as mock_req:
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.headers = {'Content-Type': 'application/json'}
            mock_res.text = '{"id": 1}'
            mock_res.json.return_value = {"id": 1}
            mock_req.return_value = mock_res

            run_resp = self.client.post(reverse('client:run_test_suite_api', kwargs={'suite_id': suite_id}))
            self.assertEqual(run_resp.status_code, 200)
            self.assertTrue(run_resp.json()['success'])
            self.assertEqual(TestSuiteRun.objects.count(), 1)

    def test_api_monitoring_and_alert_deduplication(self):
        monitor = Monitor.objects.create(
            user=self.user,
            name='Health Check Monitor',
            url='https://api.example.com/health',
            method='GET',
            expected_status=200,
            max_latency_ms=1000.0,
            interval_minutes=5
        )
        AlertRule.objects.create(user=self.user, monitor=monitor, condition='on_failure')

        # 1. Simulate Failure Check -> Creates MONITOR_DOWN Notification
        with patch('client.views.requests.request') as mock_req:
            mock_fail = MagicMock()
            mock_fail.status_code = 500
            mock_fail.headers = {}
            mock_fail.text = 'Internal Error'
            mock_req.return_value = mock_fail

            _execute_monitor(monitor)
            self.assertEqual(MonitorRun.objects.filter(monitor=monitor).count(), 1)
            self.assertFalse(MonitorRun.objects.first().is_healthy)
            self.assertEqual(Notification.objects.filter(user=self.user, alert_type='MONITOR_DOWN').count(), 1)

        # 2. Duplicate Failure Check -> Deduplication prevents 2nd identical alert
        with patch('client.views.requests.request') as mock_req:
            mock_fail = MagicMock()
            mock_fail.status_code = 500
            mock_fail.headers = {}
            mock_fail.text = 'Internal Error'
            mock_req.return_value = mock_fail

            _execute_monitor(monitor)
            self.assertEqual(Notification.objects.filter(user=self.user, alert_type='MONITOR_DOWN').count(), 1) # Still 1!

        # 3. Recovery Check -> Creates MONITOR_RECOVERED Notification
        with patch('client.views.requests.request') as mock_req:
            mock_ok = MagicMock()
            mock_ok.status_code = 200
            mock_ok.headers = {}
            mock_ok.text = 'OK'
            mock_req.return_value = mock_ok

            _execute_monitor(monitor)
            self.assertEqual(Notification.objects.filter(user=self.user, alert_type='MONITOR_RECOVERED').count(), 1)

    def test_mock_api_server(self):
        # Create Mock Endpoint
        mock_resp = self.client.post(
            reverse('client:mock_endpoints_api'),
            data=json.dumps({
                'name': 'Demo User Mock',
                'method': 'GET',
                'path': '/demo-users',
                'response_status': 200,
                'response_headers': {'Content-Type': 'application/json'},
                'response_body': '{"users": [{"id": 1, "name": "APIHub Mock User"}]}',
                'delay_ms': 50
            }),
            content_type='application/json'
        )
        self.assertEqual(mock_resp.status_code, 201)
        mock_data = mock_resp.json()['mock_endpoint']
        mock_key = mock_data['mock_key']

        # Call Public Mock Endpoint Proxy
        mock_url = reverse('client:public_mock_proxy', kwargs={'mock_key': mock_key})
        proxy_resp = self.client.get(mock_url)
        self.assertEqual(proxy_resp.status_code, 200)
        self.assertEqual(proxy_resp.json()['users'][0]['name'], 'APIHub Mock User')

    def test_api_versioning(self):
        col = Collection.objects.create(user=self.user, name='Versioned API')
        ver_resp = self.client.post(
            reverse('client:api_versions_api', kwargs={'collection_id': col.id}),
            data=json.dumps({'version_name': 'v2.0', 'status': 'ACTIVE', 'changelog': 'Added OAuth2 support'}),
            content_type='application/json'
        )
        self.assertEqual(ver_resp.status_code, 201)
        self.assertEqual(ApiVersion.objects.filter(collection=col).count(), 1)

    def test_public_shareable_documentation_secret_redaction(self):
        col = Collection.objects.create(user=self.user, name='Private API Docs')
        SavedRequest.objects.create(
            user=self.user,
            collection=col,
            name='Secure Endpoint',
            method='GET',
            url='https://api.example.com/secure',
            headers=[{'key': 'Authorization', 'value': 'Bearer secret_user_token_999'}]
        )

        # Publish Documentation
        pub_resp = self.client.post(reverse('client:publish_documentation_api', kwargs={'collection_id': col.id}))
        self.assertEqual(pub_resp.status_code, 200)
        share_key = pub_resp.json()['public_documentation']['share_key']

        # Access Public Documentation View
        pub_view = self.client.get(reverse('client:public_documentation_view', kwargs={'share_key': share_key}))
        self.assertEqual(pub_view.status_code, 200)
        self.assertContains(pub_view, 'Private API Docs')
        self.assertContains(pub_view, '[REDACTED]')
        self.assertNotContains(pub_view, 'secret_user_token_999')

    def test_global_search_api(self):
        Collection.objects.create(user=self.user, name='Searchable Collection')
        SavedRequest.objects.create(user=self.user, name='Searchable Request', method='GET', url='https://api.example.com/search')
        Monitor.objects.create(user=self.user, name='Searchable Monitor', url='https://api.example.com/health')

        resp = self.client.get(reverse('client:global_search_api') + '?q=Searchable')
        self.assertEqual(resp.status_code, 200)
        results = resp.json()['results']
        self.assertGreaterEqual(len(results), 3)

    # --- PHASE 6 TESTS ---

    def test_team_workspaces_and_roles(self):
        # 1. Create Workspace
        ws_resp = self.client.post(
            reverse('client:workspaces_api'),
            data=json.dumps({'name': 'Engineering Team', 'description': 'Shared workspace'}),
            content_type='application/json'
        )
        self.assertEqual(ws_resp.status_code, 201)
        ws_id = ws_resp.json()['workspace']['id']

        # 2. Invite user2 as VIEWER
        inv_resp = self.client.post(
            reverse('client:workspace_members_api', kwargs={'workspace_id': ws_id}),
            data=json.dumps({'target': self.user2.username, 'role': 'VIEWER'}),
            content_type='application/json'
        )
        self.assertEqual(inv_resp.status_code, 201)

        # 3. Verify user2 role restriction (VIEWER cannot modify workspace)
        self.client.login(username='otheruser', password='StrongPass#2026!')
        del_resp = self.client.delete(reverse('client:workspace_detail_api', kwargs={'workspace_id': ws_id}))
        self.assertEqual(del_resp.status_code, 403)

    def test_personal_access_token_and_bearer_auth(self):
        # 1. Generate PAT
        pat_resp = self.client.post(
            reverse('client:personal_access_tokens_api'),
            data=json.dumps({'name': 'CI Bot Token', 'expiry_days': 30}),
            content_type='application/json'
        )
        self.assertEqual(pat_resp.status_code, 201)
        raw_token = pat_resp.json()['raw_token']

        # 2. Logout session & execute API request using Bearer PAT
        self.client.logout()
        headers = {'HTTP_AUTHORIZATION': f'Bearer {raw_token}'}
        ws_resp = self.client.get(reverse('client:workspaces_api'), **headers)
        self.assertEqual(ws_resp.status_code, 200)

    def test_webhooks_and_ci_runs(self):
        ws = Workspace.objects.create(name='CI Workspace', owner=self.user)
        # Create Webhook
        wh_resp = self.client.post(
            reverse('client:webhooks_api', kwargs={'workspace_id': ws.id}),
            data=json.dumps({'name': 'CI Status Webhook', 'url': 'https://api.example.com/webhook'}),
            content_type='application/json'
        )
        self.assertEqual(wh_resp.status_code, 201)

        # Record CI Run
        ci_resp = self.client.post(
            reverse('client:ci_runs_api', kwargs={'workspace_id': ws.id}),
            data=json.dumps({
                'commit_sha': 'abc123def456',
                'branch': 'main',
                'status': 'PASSED',
                'total_count': 10,
                'passed_count': 10,
                'failed_count': 0,
                'duration_ms': 1250.0
            }),
            content_type='application/json'
        )
        self.assertEqual(ci_resp.status_code, 201)
        self.assertEqual(CiRun.objects.filter(workspace=ws).count(), 1)

    # --- PHASE 7 TESTS ---

    def test_smart_analysis_local_and_schema_generation(self):
        payload = {
            'status_code': 200,
            'status_text': 'OK',
            'response_time_ms': 180.5,
            'response_size_kb': 2.4,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'id': 101, 'name': 'Test User', 'roles': ['admin', 'editor']}),
            'url': 'https://api.example.com/users/101',
            'method': 'GET'
        }
        resp = self.client.post(
            reverse('client:smart_analysis_api'),
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data['mode'], 'local')
        self.assertIn('Smart Local Analysis', data['mode_label'])
        self.assertTrue(data['is_json'])
        self.assertIn('properties', data['json_schema'])
        self.assertIn('schema', data['openapi_schema']['content']['application/json'])
        self.assertGreaterEqual(len(data['suggested_tests']), 3)

    def test_http_status_explainer(self):
        resp = self.client.get(reverse('client:status_explainer_api', kwargs={'status_code': 404}))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn('404 Not Found', data['explanation']['title'])
        self.assertIn('suggested_checks', data['explanation'])

    def test_code_generator_all_languages_with_secret_redaction(self):
        payload = {
            'method': 'POST',
            'url': 'https://api.example.com/posts',
            'headers': [{'key': 'Authorization', 'value': 'Bearer secret-key-999'}],
            'params': [{'key': 'version', 'value': 'v1'}],
            'body': '{"title": "Test Post"}'
        }
        resp = self.client.post(
            reverse('client:code_generator_api'),
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 200)
        codes = resp.json()
        self.assertIn('curl', codes)
        self.assertIn('python', codes)
        self.assertIn('javascript_fetch', codes)
        self.assertIn('javascript_axios', codes)
        self.assertIn('go', codes)
        self.assertIn('php', codes)
        self.assertIn('java', codes)
        # Verify secret redaction
        self.assertNotIn('secret-key-999', codes['curl'])
        self.assertIn('{{token}}', codes['curl'])

    def test_request_and_response_diff_tools(self):
        col = Collection.objects.create(user=self.user, name='Diff Collection')
        req1 = SavedRequest.objects.create(user=self.user, collection=col, name='Req 1', method='GET', url='https://api.example.com/v1')
        req2 = SavedRequest.objects.create(user=self.user, collection=col, name='Req 2', method='POST', url='https://api.example.com/v2')

        # 1. Request Diff
        req_diff_resp = self.client.post(
            reverse('client:diff_requests_api'),
            data=json.dumps({'request_1_id': req1.id, 'request_2_id': req2.id}),
            content_type='application/json'
        )
        self.assertEqual(req_diff_resp.status_code, 200)
        self.assertFalse(req_diff_resp.json()['diff']['method_diff']['same'])

        # 2. Response JSON Diff
        resp_diff_resp = self.client.post(
            reverse('client:diff_responses_api'),
            data=json.dumps({
                'response_a': '{"id": 1, "name": "Aayush"}',
                'response_b': '{"id": 1, "name": "Aayush", "phone": "123"}'
            }),
            content_type='application/json'
        )
        self.assertEqual(resp_diff_resp.status_code, 200)
        diff_data = resp_diff_resp.json()
        self.assertEqual(len(diff_data['added']), 1)
        self.assertEqual(diff_data['added'][0]['path'], '$.phone')

    def test_workspace_health_and_completeness_score(self):
        col = Collection.objects.create(user=self.user, name='Health Col')
        SavedRequest.objects.create(user=self.user, collection=col, name='Full Req', method='GET', url='https://api.example.com/data', description='Has description', tests=[{'name': 'Test'}], contract_schema={'type': 'object'})

        resp = self.client.get(reverse('client:workspace_health_api'))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(data['configuration_completeness_score'], 90.0)
        self.assertIn('scoring_rules', data)

    def test_preflight_check(self):
        resp = self.client.post(
            reverse('client:preflight_check_api'),
            data=json.dumps({
                'url': 'invalid-url-without-scheme',
                'body': '{ malformed json }'
            }),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(len(data['warnings']) >= 2)

    def test_archive_resource_and_bulk_actions(self):
        col = Collection.objects.create(user=self.user, name='Archive Collection')
        req1 = SavedRequest.objects.create(user=self.user, collection=col, name='Req 1', method='GET', url='https://api.example.com/1')
        req2 = SavedRequest.objects.create(user=self.user, collection=col, name='Req 2', method='POST', url='https://api.example.com/2')

        # Single Archive
        arc_resp = self.client.post(
            reverse('client:archive_resource_api'),
            data=json.dumps({'resource_type': 'request', 'resource_id': req1.id, 'action': 'archive'}),
            content_type='application/json'
        )
        self.assertEqual(arc_resp.status_code, 200)
        self.assertTrue(SavedRequest.objects.get(id=req1.id).is_archived)

        # Bulk Export JSON
        bulk_resp = self.client.post(
            reverse('client:bulk_actions_api'),
            data=json.dumps({'request_ids': [req1.id, req2.id], 'action': 'export_json'}),
            content_type='application/json'
        )
        self.assertEqual(bulk_resp.status_code, 200)
        self.assertEqual(len(bulk_resp.json()['apihub_export']), 2)

    def test_demo_mode_initialization(self):
        resp = self.client.post(reverse('client:demo_mode_api'))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data['success'])
        self.assertTrue(Workspace.objects.filter(owner=self.user, is_demo=True).exists())

