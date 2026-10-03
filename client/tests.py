import json
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from client.models import (
    RequestHistory, Collection, SavedRequest, Environment, EnvironmentVariable,
    AuditLog, UserSettings
)


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
        # Test Logout
        self.client.logout()
        idx_resp = self.client.get(reverse('client:index'))
        self.assertEqual(idx_resp.status_code, 302)  # Redirect to login

        # Test Registration while unauthenticated
        reg_resp = self.client.post(reverse('client:register'), {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'Complex#Pass9876!',
            'confirm_password': 'Complex#Pass9876!'
        })
        self.assertEqual(reg_resp.status_code, 302)
        self.assertTrue(User.objects.filter(username='newuser').exists())

        # Test Logout again & Test Login
        self.client.logout()
        login_resp = self.client.post(reverse('client:login'), {'username': 'testuser', 'password': 'StrongPass#2026!'})
        self.assertEqual(login_resp.status_code, 302)

    def test_user_data_isolation(self):
        # Create collection as User 1
        col1 = Collection.objects.create(user=self.user, name='User 1 Collection')
        # Create collection as User 2
        col2 = Collection.objects.create(user=self.user2, name='User 2 Collection')

        # Get collections as User 1
        resp = self.client.get(reverse('client:collections_api'))
        self.assertEqual(resp.status_code, 200)
        cols = resp.json()['collections']
        self.assertEqual(len(cols), 1)
        self.assertEqual(cols[0]['name'], 'User 1 Collection')

        # User 1 attempts to access User 2's collection detail
        detail_resp = self.client.get(reverse('client:collection_detail_api', kwargs={'collection_id': col2.id}))
        self.assertEqual(detail_resp.status_code, 404)

        # User 1 attempts to delete User 2's collection detail
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
        data = response.json()
        self.assertEqual(data['status_code'], 200)

        # Check DB entry created and Authorization header REDACTED in DB
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

    def test_history_api(self):
        RequestHistory.objects.create(
            user=self.user,
            method='POST',
            url='https://example.com/api',
            headers={'Accept': 'application/json'},
            params={},
            body='{"test": 1}',
            status_code=201,
            status_text='Created',
            response_time_ms=120.5,
            response_size_kb=1.2,
        )

        response = self.client.get(reverse('client:history_api'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['history']), 1)
        self.assertEqual(data['history'][0]['method'], 'POST')

        # Test DELETE history
        del_resp = self.client.delete(reverse('client:history_api'))
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(RequestHistory.objects.filter(user=self.user).count(), 0)

    def test_collections_crud(self):
        col_data = {'name': 'User APIs', 'description': 'APIs related to users'}
        resp = self.client.post(
            reverse('client:collections_api'),
            data=json.dumps(col_data),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 201)
        col_id = resp.json()['collection']['id']

        up_resp = self.client.put(
            reverse('client:collection_detail_api', kwargs={'collection_id': col_id}),
            data=json.dumps({'name': 'User Management APIs'}),
            content_type='application/json'
        )
        self.assertEqual(up_resp.status_code, 200)
        self.assertEqual(up_resp.json()['collection']['name'], 'User Management APIs')

        del_resp = self.client.delete(
            reverse('client:collection_detail_api', kwargs={'collection_id': col_id})
        )
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(Collection.objects.count(), 0)

    def test_saved_requests_crud_and_duplicate(self):
        col = Collection.objects.create(user=self.user, name='Auth APIs', description='Auth endpoints')
        req_payload = {
            'collection_id': col.id,
            'name': 'Login Request',
            'method': 'POST',
            'url': 'https://example.com/api/login',
            'headers': [{'key': 'Content-Type', 'value': 'application/json'}],
            'body': '{"user": "admin"}'
        }

        resp = self.client.post(
            reverse('client:saved_requests_api'),
            data=json.dumps(req_payload),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 201)
        req_id = resp.json()['request']['id']

        dup_resp = self.client.post(
            reverse('client:duplicate_request_api', kwargs={'request_id': req_id})
        )
        self.assertEqual(dup_resp.status_code, 201)
        self.assertEqual(SavedRequest.objects.count(), 2)

    def test_environments_and_variables_crud(self):
        env_resp = self.client.post(
            reverse('client:environments_api'),
            data=json.dumps({'name': 'Development'}),
            content_type='application/json'
        )
        self.assertEqual(env_resp.status_code, 201)
        env_id = env_resp.json()['environment']['id']

        var_resp = self.client.post(
            reverse('client:variables_api'),
            data=json.dumps({'environment_id': env_id, 'key': 'base_url', 'value': 'http://localhost:8000'}),
            content_type='application/json'
        )
        self.assertEqual(var_resp.status_code, 201)

    def test_assertions_evaluation(self):
        from client.views import _evaluate_assertions, _evaluate_json_path

        sample_json = {
            "id": 1,
            "user": {"email": "test@example.com"},
            "items": [{"id": 10}, {"id": 20}]
        }
        found, val = _evaluate_json_path(sample_json, "user.email")
        self.assertTrue(found)
        self.assertEqual(val, "test@example.com")

        tests = [
            {'name': 'Status 200', 'operator': 'equals', 'expected': '200'},
            {'name': 'Latency Check', 'operator': 'less_than', 'expected': '500'},
        ]
        context = {
            'status_code': 200,
            'time_ms': 150.0,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps(sample_json),
            'data': sample_json,
            'is_json': True
        }
        results, summary = _evaluate_assertions(tests, context)
        self.assertEqual(summary['passed'], 2)

    @patch('client.views.requests.request')
    def test_run_collection_api(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.reason = 'OK'
        mock_resp.headers = {'Content-Type': 'application/json'}
        mock_resp.text = '{"userId": 1, "id": 1}'
        mock_resp.json.return_value = {"userId": 1, "id": 1}
        mock_request.return_value = mock_resp

        col = Collection.objects.create(user=self.user, name='Runner Test Collection')
        SavedRequest.objects.create(
            user=self.user,
            collection=col,
            name='Req 1',
            method='GET',
            url='https://jsonplaceholder.typicode.com/posts/1',
            tests=[{'name': 'Status 200', 'operator': 'equals', 'expected': '200'}]
        )

        resp = self.client.post(reverse('client:run_collection_api', kwargs={'collection_id': col.id}))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data['success'])

    def test_import_and_export_postman(self):
        postman_data = {
            'info': {'name': 'Imported Postman Test', 'description': 'Test collection'},
            'item': [{'name': 'Get Posts', 'request': {'method': 'GET', 'url': {'raw': 'https://jsonplaceholder.typicode.com/posts'}}}]
        }

        imp_resp = self.client.post(
            reverse('client:import_postman_api'),
            data=json.dumps(postman_data),
            content_type='application/json'
        )
        self.assertEqual(imp_resp.status_code, 201)
        col_id = imp_resp.json()['collection']['id']

        exp_resp = self.client.get(reverse('client:export_postman_api', kwargs={'collection_id': col_id}))
        self.assertEqual(exp_resp.status_code, 200)

    def test_audit_logs_recorded(self):
        # Create a collection to generate audit log
        self.client.post(
            reverse('client:collections_api'),
            data=json.dumps({'name': 'Audit Test Collection'}),
            content_type='application/json'
        )
        self.assertTrue(AuditLog.objects.filter(user=self.user, action='CREATE_COLLECTION').exists())

    def test_export_account_data(self):
        resp = self.client.get(reverse('client:export_account_data'))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data['user']['username'], 'testuser')
