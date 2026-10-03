from django.urls import path
from . import views

app_name = 'client'

urlpatterns = [
    # Health & System Status
    path('health/', views.health_view, name='health'),
    path('ready/', views.ready_view, name='ready'),

    # Authentication & Profile
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('settings/', views.settings_view, name='settings'),
    path('export-data/', views.export_account_data, name='export_account_data'),
    path('delete-account/', views.delete_account, name='delete_account'),

    # SPA Main View
    path('', views.index, name='index'),

    # Public Mock Endpoint Route
    path('api/mock/<str:mock_key>/', views.public_mock_proxy, name='public_mock_proxy'),
    path('api/mock/<str:mock_key>/<path:extra_path>', views.public_mock_proxy, name='public_mock_proxy_path'),

    # Public Shareable Documentation
    path('docs/public/<str:share_key>/', views.public_documentation_view, name='public_documentation_view'),

    # Core Execution & History API
    path('api/execute/', views.execute_request, name='execute_request'),
    path('api/history/', views.history_api, name='history_api'),
    path('api/search/', views.global_search_api, name='global_search_api'),

    # Phase 2 Endpoints
    path('api/collections/', views.collections_api, name='collections_api'),
    path('api/collections/<int:collection_id>/', views.collection_detail_api, name='collection_detail_api'),

    path('api/requests/', views.saved_requests_api, name='saved_requests_api'),
    path('api/requests/<int:request_id>/', views.saved_request_detail_api, name='saved_request_detail_api'),
    path('api/requests/<int:request_id>/duplicate/', views.duplicate_request_api, name='duplicate_request_api'),

    path('api/environments/', views.environments_api, name='environments_api'),
    path('api/environments/<int:environment_id>/', views.environment_detail_api, name='environment_detail_api'),

    path('api/variables/', views.variables_api, name='variables_api'),
    path('api/variables/<int:variable_id>/', views.variable_detail_api, name='variable_detail_api'),

    # Phase 3 Endpoints
    path('api/collections/<int:collection_id>/run/', views.run_collection_api, name='run_collection_api'),
    path('api/collections/<int:collection_id>/export/postman/', views.export_postman_api, name='export_postman_api'),
    path('api/collections/<int:collection_id>/documentation/', views.collection_documentation_api, name='collection_documentation_api'),
    path('api/import/postman/', views.import_postman_api, name='import_postman_api'),
    path('api/import/request/', views.import_request_api, name='import_request_api'),
    path('api/analytics/', views.analytics_api, name='analytics_api'),

    # Phase 5 Endpoints
    path('api/import/openapi/', views.import_openapi_api, name='import_openapi_api'),
    path('api/collections/<int:collection_id>/export/openapi/', views.export_openapi_api, name='export_openapi_api'),

    path('api/test-suites/', views.test_suites_api, name='test_suites_api'),
    path('api/test-suites/<int:suite_id>/', views.test_suite_detail_api, name='test_suite_detail_api'),
    path('api/test-suites/<int:suite_id>/run/', views.run_test_suite_api, name='run_test_suite_api'),

    path('api/monitors/', views.monitors_api, name='monitors_api'),
    path('api/monitors/<int:monitor_id>/', views.monitor_detail_api, name='monitor_detail_api'),
    path('api/monitors/<int:monitor_id>/run/', views.run_monitor_now_api, name='run_monitor_now_api'),
    path('api/monitors/dashboard/', views.monitors_dashboard_api, name='monitors_dashboard_api'),

    path('api/notifications/', views.notifications_api, name='notifications_api'),

    path('api/mocks/', views.mock_endpoints_api, name='mock_endpoints_api'),
    path('api/mocks/<int:mock_id>/', views.mock_endpoint_detail_api, name='mock_endpoint_detail_api'),

    path('api/collections/<int:collection_id>/versions/', views.api_versions_api, name='api_versions_api'),
    path('api/versions/<int:version_id>/', views.api_version_detail_api, name='api_version_detail_api'),

    path('api/collections/<int:collection_id>/publish/', views.publish_documentation_api, name='publish_documentation_api'),
]
