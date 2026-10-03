import json
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.urls import reverse
from client.models import RequestHistory, Collection, SavedRequest, Environment, EnvironmentVariable


class APIHubTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_index_page_loads(self):
        response = self.client.get(reverse('client:index'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'APIHub')
        self.assertContains(response, 'Postman')

    @patch('client.views.requests.request')
    def test_execute_request_success(self, mock_request):
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
            'headers': [{'key': 'Accept', 'value': 'application/json'}],
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
        self.assertEqual(data['status_text'], 'OK')
        self.assertEqual(data['data']['title'], 'Test Title')
        self.assertTrue(data['is_json'])
        self.assertGreaterEqual(data['time_ms'], 0)

        # Check DB entry created
        self.assertEqual(RequestHistory.objects.count(), 1)
        entry = RequestHistory.objects.first()
        self.assertEqual(entry.method, 'GET')
        self.assertEqual(entry.status_code, 200)

    def test_history_api(self):
        RequestHistory.objects.create(
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
        self.assertEqual(data['history'][0]['status_code'], 201)

        # Test DELETE history
        del_resp = self.client.delete(reverse('client:history_api'))
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(RequestHistory.objects.count(), 0)

    def test_collections_crud(self):
        # 1. Create collection
        col_data = {'name': 'User APIs', 'description': 'APIs related to users'}
        resp = self.client.post(
            reverse('client:collections_api'),
            data=json.dumps(col_data),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 201)
        res_json = resp.json()
        self.assertTrue(res_json['success'])
        col_id = res_json['collection']['id']

        # 2. Get collections
        get_resp = self.client.get(reverse('client:collections_api'))
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(len(get_resp.json()['collections']), 1)

        # 3. Update collection
        up_resp = self.client.put(
            reverse('client:collection_detail_api', kwargs={'collection_id': col_id}),
            data=json.dumps({'name': 'User Management APIs'}),
            content_type='application/json'
        )
        self.assertEqual(up_resp.status_code, 200)
        self.assertEqual(up_resp.json()['collection']['name'], 'User Management APIs')

        # 4. Delete collection
        del_resp = self.client.delete(
            reverse('client:collection_detail_api', kwargs={'collection_id': col_id})
        )
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(Collection.objects.count(), 0)

    def test_saved_requests_crud_and_duplicate(self):
        col = Collection.objects.create(name='Auth APIs', description='Auth endpoints')
        req_payload = {
            'collection_id': col.id,
            'name': 'Login Request',
            'method': 'POST',
            'url': 'https://example.com/api/login',
            'headers': [{'key': 'Content-Type', 'value': 'application/json'}],
            'body': '{"user": "admin"}'
        }

        # 1. Create saved request
        resp = self.client.post(
            reverse('client:saved_requests_api'),
            data=json.dumps(req_payload),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 201)
        req_id = resp.json()['request']['id']

        # 2. Duplicate saved request
        dup_resp = self.client.post(
            reverse('client:duplicate_request_api', kwargs={'request_id': req_id})
        )
        self.assertEqual(dup_resp.status_code, 201)
        dup_data = dup_resp.json()['request']
        self.assertEqual(dup_data['name'], 'Login Request Copy')
        self.assertEqual(SavedRequest.objects.count(), 2)

        # 3. Delete request
        del_resp = self.client.delete(
            reverse('client:saved_request_detail_api', kwargs={'request_id': req_id})
        )
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(SavedRequest.objects.count(), 1)

    def test_environments_and_variables_crud(self):
        # 1. Create environment
        env_resp = self.client.post(
            reverse('client:environments_api'),
            data=json.dumps({'name': 'Development'}),
            content_type='application/json'
        )
        self.assertEqual(env_resp.status_code, 201)
        env_id = env_resp.json()['environment']['id']

        # 2. Add variable
        var_resp = self.client.post(
            reverse('client:variables_api'),
            data=json.dumps({'environment_id': env_id, 'key': 'base_url', 'value': 'http://localhost:8000'}),
            content_type='application/json'
        )
        self.assertEqual(var_resp.status_code, 201)
        var_id = var_resp.json()['variable']['id']

        # 3. Update variable
        up_var_resp = self.client.put(
            reverse('client:variable_detail_api', kwargs={'variable_id': var_id}),
            data=json.dumps({'key': 'base_url', 'value': 'http://localhost:8080'}),
            content_type='application/json'
        )
        self.assertEqual(up_var_resp.status_code, 200)
        self.assertEqual(up_var_resp.json()['variable']['value'], 'http://localhost:8080')

        # 4. Delete variable
        del_var_resp = self.client.delete(
            reverse('client:variable_detail_api', kwargs={'variable_id': var_id})
        )
        self.assertEqual(del_var_resp.status_code, 200)
        self.assertEqual(EnvironmentVariable.objects.count(), 0)

    @patch('client.views.requests.request')
    def test_variable_substitution_in_execute_request(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.reason = 'OK'
        mock_resp.headers = {'Content-Type': 'application/json'}
        mock_resp.content = b'{"success": true}'
        mock_resp.json.return_value = {"success": True}
        mock_resp.text = '{"success": true}'
        mock_request.return_value = mock_resp

        # Create environment with variable
        env = Environment.objects.create(name='Staging')
        EnvironmentVariable.objects.create(environment=env, key='host', value='api.staging.com')
        EnvironmentVariable.objects.create(environment=env, key='post_id', value='42')

        payload = {
            'environment_id': env.id,
            'method': 'GET',
            'url': 'https://{{host}}/posts/{{post_id}}',
            'headers': [{'key': 'X-Host', 'value': '{{host}}'}],
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
        # Verify requests.request was called with substituted URL
        mock_request.assert_called_once()
        call_kwargs = mock_request.call_args[1]
        self.assertEqual(call_kwargs['url'], 'https://api.staging.com/posts/42')
        self.assertEqual(call_kwargs['headers']['X-Host'], 'api.staging.com')

    # --- PHASE 3 UNIT TESTS ---

    def test_assertions_evaluation(self):
        from client.views import _evaluate_assertions, _evaluate_json_path

        # Test JSONPath evaluator
        sample_json = {
            "id": 1,
            "user": {"email": "test@example.com"},
            "items": [{"id": 10}, {"id": 20}]
        }
        found, val = _evaluate_json_path(sample_json, "user.email")
        self.assertTrue(found)
        self.assertEqual(val, "test@example.com")

        found_idx, val_idx = _evaluate_json_path(sample_json, "items[1].id")
        self.assertTrue(found_idx)
        self.assertEqual(val_idx, 20)

        found_none, _ = _evaluate_json_path(sample_json, "user.nonexistent")
        self.assertFalse(found_none)

        # Test Assertion Evaluator
        tests = [
            {'name': 'Status 200', 'operator': 'equals', 'expected': '200'},
            {'name': 'Latency Check', 'operator': 'less_than', 'expected': '500'},
            {'name': 'Body Contains', 'operator': 'contains', 'expected': 'example.com'},
            {'name': 'JSON Path Email', 'operator': 'json_path_equals', 'expected': 'test@example.com', 'path': 'user.email'},
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
        self.assertEqual(summary['total'], 4)
        self.assertEqual(summary['passed'], 4)
        self.assertEqual(summary['failed'], 0)

    def test_ssrf_and_security_filtering(self):
        from client.views import _is_safe_url

        is_safe, msg = _is_safe_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(is_safe)
        self.assertIn("blocked", msg)

        is_safe_ext, _ = _is_safe_url("https://api.example.com/data")
        self.assertTrue(is_safe_ext)

    @patch('client.views.requests.request')
    def test_run_collection_api(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.reason = 'OK'
        mock_resp.headers = {'Content-Type': 'application/json'}
        mock_resp.text = '{"userId": 1, "id": 1}'
        mock_resp.json.return_value = {"userId": 1, "id": 1}
        mock_request.return_value = mock_resp

        col = Collection.objects.create(name='Runner Test Collection')
        SavedRequest.objects.create(
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
        self.assertEqual(data['total_tests'], 1)
        self.assertEqual(data['passed_tests'], 1)
        self.assertEqual(data['failed_tests'], 0)

    def test_import_and_export_postman(self):
        postman_data = {
            'info': {
                'name': 'Imported Postman Test',
                'description': 'Test collection'
            },
            'item': [
                {
                    'name': 'Get Posts',
                    'request': {
                        'method': 'GET',
                        'url': {'raw': 'https://jsonplaceholder.typicode.com/posts'},
                        'header': [{'key': 'Accept', 'value': 'application/json'}]
                    }
                }
            ]
        }

        # Test Import
        imp_resp = self.client.post(
            reverse('client:import_postman_api'),
            data=json.dumps(postman_data),
            content_type='application/json'
        )
        self.assertEqual(imp_resp.status_code, 201)
        col_id = imp_resp.json()['collection']['id']

        # Test Export
        exp_resp = self.client.get(reverse('client:export_postman_api', kwargs={'collection_id': col_id}))
        self.assertEqual(exp_resp.status_code, 200)
        exp_json = exp_resp.json()
        self.assertEqual(exp_json['info']['name'], 'Imported Postman Test')
        self.assertEqual(len(exp_json['item']), 1)

    def test_import_request_api(self):
        req_data = {
            'name': 'Standalone Request',
            'method': 'POST',
            'url': 'https://httpbin.org/post',
            'headers': [{'key': 'Content-Type', 'value': 'application/json'}],
            'body': '{"key": "value"}'
        }
        resp = self.client.post(
            reverse('client:import_request_api'),
            data=json.dumps(req_data),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(resp.json()['success'])
        self.assertEqual(SavedRequest.objects.filter(name='Standalone Request').count(), 1)

    def test_collection_documentation_api(self):
        col = Collection.objects.create(name='Doc Collection', description='API Docs')
        SavedRequest.objects.create(
            collection=col,
            name='GetUser',
            method='GET',
            url='https://api.example.com/user',
            description='Retrieves current user'
        )

        resp = self.client.get(reverse('client:collection_documentation_api', kwargs={'collection_id': col.id}))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn('# Doc Collection', data['markdown'])
        self.assertIn('GET `https://api.example.com/user`', data['markdown'])

    def test_analytics_api(self):
        RequestHistory.objects.create(
            method='GET',
            url='https://api.example.com/1',
            status_code=200,
            response_time_ms=100.0
        )
        RequestHistory.objects.create(
            method='POST',
            url='https://api.example.com/2',
            status_code=400,
            response_time_ms=300.0
        )

        resp = self.client.get(reverse('client:analytics_api') + '?range=all')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data['total_requests'], 2)
        self.assertEqual(data['success_rate'], 50.0)
        self.assertEqual(data['avg_response_time_ms'], 200.0)
        self.assertEqual(data['status_distribution']['2xx'], 1)
        self.assertEqual(data['status_distribution']['4xx'], 1)

