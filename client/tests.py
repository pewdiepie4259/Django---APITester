import json
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.urls import reverse
from client.models import RequestHistory


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
        # Mock requests.request response
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
        # Create a test entry
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
