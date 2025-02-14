/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api/"
#define USERNAME "user1"
#define PASSWORD "password"
#define SCOPE_LIST "scope1 scope2"
#define SCOPE_LIST_PARTIAL "scope1"
#define SCOPE_LIST_MAX_USE "scope1 scope2 scope3"
#define CLIENT "client1_id"

struct _u_request user_req;
char * code;

START_TEST(test_oauth2_code_code_invalid)
{
  char * url = msprintf("%s/glwd/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", "../../test-oauth2.html?param=client1_cb1");
  u_map_put(&body, "code", "invalid");
  
  o_free(user_req.http_verb);
  user_req.http_verb = NULL;
  int res = run_simple_test(&user_req, "POST", url, NULL, NULL, NULL, &body, 403, NULL, NULL, NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oauth2_code_client_invalid)
{
  char * url = msprintf("%s/glwd/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "client_id", "invalid");
  u_map_put(&body, "redirect_uri", "../../test-oauth2.html?param=client1_cb1");
  u_map_put(&body, "code", code);
  
  o_free(user_req.http_verb);
  user_req.http_verb = NULL;
  int res = run_simple_test(&user_req, "POST", url, NULL, NULL, NULL, &body, 403, NULL, "unauthorized_client", NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oauth2_code_redirect_uri_invalid)
{
  char * url = msprintf("%s/glwd/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", "invalid");
  u_map_put(&body, "code", code);
  
  o_free(user_req.http_verb);
  user_req.http_verb = NULL;
  int res = run_simple_test(&user_req, "POST", url, NULL, NULL, NULL, &body, 403, NULL, NULL, NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oauth2_code_ok)
{
  char * url = msprintf("%s/glwd/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", "../../test-oauth2.html?param=client1_cb1");
  u_map_put(&body, "code", code);
  
  o_free(user_req.http_verb);
  user_req.http_verb = NULL;
  ck_assert_int_eq(run_simple_test(&user_req, "POST", url, NULL, NULL, NULL, &body, 200, NULL, "refresh_token", NULL), 1);
  o_free(url);
  u_map_clean(&body);
}
END_TEST

START_TEST(test_oauth2_code_scope_grant_partial)
{
  struct _u_request auth_req, code_req;
  struct _u_response auth_resp, code_resp;
  json_t * j_body;
  char * cookie, * code;

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_request(&code_req);
  ulfius_init_response(&code_resp);

  // Authenticate with password
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  // Get session cookie
  cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
  u_map_put(auth_req.map_header, "Cookie", cookie);
  u_map_put(code_req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_response(&auth_resp);

  // Grant access to scopes
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("PUT");
  auth_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", SCOPE_LIST_PARTIAL);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 42
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 95
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Get code
  code_req.http_verb = strdup("GET");
  code_req.http_url = msprintf("%s/glwd/auth?response_type=code&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oauth2.html%%3fparam%%3dclient1_cb1&scope=%s", SERVER_URI, CLIENT, SCOPE_LIST);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(code_resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(code_resp.map_header, "Location"), "code=")+o_strlen("code="));
  ck_assert_ptr_ne(code, NULL);
  ulfius_clean_response(&code_resp);

  // Get refresh token from code
  ulfius_init_response(&code_resp);
  o_free(code_req.http_verb);
  o_free(code_req.http_url);
  code_req.http_verb = strdup("POST");
  code_req.http_url = msprintf("%s/glwd/token/", SERVER_URI);
  u_map_put(code_req.map_post_body, "grant_type", "authorization_code");
  u_map_put(code_req.map_post_body, "client_id", CLIENT);
  u_map_put(code_req.map_post_body, "redirect_uri", "../../test-oauth2.html?param=client1_cb1");
  u_map_put(code_req.map_post_body, "code", code);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 200);
  j_body = ulfius_get_json_body_response(&code_resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_body, "scope")), SCOPE_LIST_PARTIAL);
  ulfius_clean_request(&code_req);
  ulfius_clean_response(&code_resp);
  o_free(code);
  json_decref(j_body);

  // Clean grant scopes
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("PUT");
  auth_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);

  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST

START_TEST(test_oauth2_code_scope_grant_none)
{
  struct _u_request auth_req, code_req;
  struct _u_response auth_resp, code_resp;
  json_t * j_body;
  char * cookie;

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_request(&code_req);
  ulfius_init_response(&code_resp);

  // Authenticate with password
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  // Get session cookie
  cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
  u_map_put(auth_req.map_header, "Cookie", cookie);
  u_map_put(code_req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 42
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 95
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Try to get code
  code_req.http_verb = strdup("GET");
  code_req.http_url = msprintf("%s/glwd/auth?response_type=code&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oauth2.html%%3fparam%%3dclient1_cb1&scope=%s", SERVER_URI, CLIENT, SCOPE_LIST);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(code_resp.map_header, "Location"), "invalid_scope"), NULL);

  ulfius_clean_request(&code_req);
  ulfius_clean_response(&code_resp);
  ulfius_clean_request(&auth_req);
}
END_TEST

START_TEST(test_oauth2_code_scope_grant_all_authorize_partial)
{
  struct _u_request auth_req, code_req;
  struct _u_response auth_resp, code_resp;
  json_t * j_body;
  char * cookie;

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_request(&code_req);
  ulfius_init_response(&code_resp);

  // Authenticate with password
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  // Get session cookie
  cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
  u_map_put(auth_req.map_header, "Cookie", cookie);
  u_map_put(code_req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_response(&auth_resp);

  // Grant access to scopes
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("PUT");
  auth_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 95
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Try to get code
  code_req.http_verb = strdup("GET");
  code_req.http_url = msprintf("%s/glwd/auth?response_type=code&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oauth2.html%%3fparam%%3dclient1_cb1&scope=%s", SERVER_URI, CLIENT, SCOPE_LIST);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(code_resp.map_header, "Location"), "login.html"), NULL);
  ulfius_clean_response(&code_resp);

  // Clean grant scopes
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("PUT");
  auth_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);

  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&code_req);
}
END_TEST

START_TEST(test_oauth2_code_retry_with_max_use)
{
  struct _u_request auth_req, code_req;
  struct _u_response auth_resp, code_resp;
  json_t * j_body;
  char * cookie, * code;

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_request(&code_req);
  ulfius_init_response(&code_resp);

  // Authenticate with password
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  // Get session cookie
  cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
  u_map_put(auth_req.map_header, "Cookie", cookie);
  u_map_put(code_req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_response(&auth_resp);

  // Grant access to scopes
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("PUT");
  auth_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", SCOPE_LIST_MAX_USE);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 42
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 95
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 88
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "code", "88");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Get code
  code_req.http_verb = strdup("GET");
  code_req.http_url = msprintf("%s/glwd/auth?response_type=code&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oauth2.html%%3fparam%%3dclient1_cb1&scope=%s", SERVER_URI, CLIENT, SCOPE_LIST_MAX_USE);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(code_resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(code_resp.map_header, "Location"), "code=")+o_strlen("code="));
  ck_assert_ptr_ne(code, NULL);
  ulfius_clean_response(&code_resp);

  // Get refresh token from code
  ulfius_init_response(&code_resp);
  o_free(code_req.http_verb);
  o_free(code_req.http_url);
  code_req.http_verb = strdup("POST");
  code_req.http_url = msprintf("%s/glwd/token/", SERVER_URI);
  u_map_put(code_req.map_post_body, "grant_type", "authorization_code");
  u_map_put(code_req.map_post_body, "client_id", CLIENT);
  u_map_put(code_req.map_post_body, "redirect_uri", "../../test-oauth2.html?param=client1_cb1");
  u_map_put(code_req.map_post_body, "code", code);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 200);
  j_body = ulfius_get_json_body_response(&code_resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_body, "scope")), SCOPE_LIST_MAX_USE);
  ulfius_clean_response(&code_resp);
  o_free(code);
  json_decref(j_body);

  // Try to get another code with the same session but redirected to login page
  ulfius_init_response(&code_resp);
  o_free(code_req.http_verb);
  o_free(code_req.http_url);
  code_req.http_verb = strdup("GET");
  code_req.http_url = msprintf("%s/glwd/auth?response_type=code&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oauth2.html%%3fparam%%3dclient1_cb1&scope=%s", SERVER_URI, CLIENT, SCOPE_LIST_MAX_USE);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(code_resp.map_header, "Location"), "login.html"), NULL);
  ulfius_clean_response(&code_resp);

  // Reauthenticate with scheme mock 88
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "code", "88");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Get another code
  ulfius_init_response(&code_resp);
  o_free(code_req.http_verb);
  o_free(code_req.http_url);
  code_req.http_verb = strdup("GET");
  code_req.http_url = msprintf("%s/glwd/auth?response_type=code&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oauth2.html%%3fparam%%3dclient1_cb1&scope=%s", SERVER_URI, CLIENT, SCOPE_LIST_MAX_USE);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(code_resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(code_resp.map_header, "Location"), "code=")+o_strlen("code="));
  ck_assert_ptr_ne(code, NULL);
  ulfius_clean_response(&code_resp);

  // Get another refresh token from code
  ulfius_init_response(&code_resp);
  o_free(code_req.http_verb);
  o_free(code_req.http_url);
  code_req.http_verb = strdup("POST");
  code_req.http_url = msprintf("%s/glwd/token/", SERVER_URI);
  u_map_put(code_req.map_post_body, "grant_type", "authorization_code");
  u_map_put(code_req.map_post_body, "client_id", CLIENT);
  u_map_put(code_req.map_post_body, "redirect_uri", "../../test-oauth2.html?param=client1_cb1");
  u_map_put(code_req.map_post_body, "code", code);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 200);
  j_body = ulfius_get_json_body_response(&code_resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_body, "scope")), SCOPE_LIST_MAX_USE);
  ulfius_clean_request(&code_req);
  ulfius_clean_response(&code_resp);
  o_free(code);
  json_decref(j_body);

  // Clean grant scopes
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("PUT");
  auth_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);

  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd code");
  tc_core = tcase_create("test_oauth2_code");
  tcase_add_test(tc_core, test_oauth2_code_code_invalid);
  tcase_add_test(tc_core, test_oauth2_code_client_invalid);
  tcase_add_test(tc_core, test_oauth2_code_redirect_uri_invalid);
  tcase_add_test(tc_core, test_oauth2_code_ok);
  tcase_add_test(tc_core, test_oauth2_code_scope_grant_partial);
  tcase_add_test(tc_core, test_oauth2_code_scope_grant_none);
  tcase_add_test(tc_core, test_oauth2_code_scope_grant_all_authorize_partial);
  tcase_add_test(tc_core, test_oauth2_code_retry_with_max_use);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req, scope_req, register_req;
  struct _u_response auth_resp, scope_resp, code_resp;
  json_t * j_body, * j_register;
  int res, do_test = 0, i;
  char * url;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
  ulfius_init_request(&scope_req);
  ulfius_init_request(&register_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_response(&scope_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    for (i=0; i<auth_resp.nb_cookies; i++) {
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(user_req.map_header, "Cookie", cookie);
      u_map_put(auth_req.map_header, "Cookie", cookie);
      u_map_put(scope_req.map_header, "Cookie", cookie);
      u_map_put(register_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    ulfius_clean_response(&auth_resp);
    ulfius_init_response(&auth_resp);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_true());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
    ulfius_set_json_body_request(&auth_req, j_body);
    json_decref(j_body);
    res = ulfius_send_http_request(&auth_req, &auth_resp);
    if (res == U_OK && auth_resp.status == 200) {
      
      j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_true());
      run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
      json_decref(j_register);
    
      j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "register", json_true());
      run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
      json_decref(j_register);
    
      ulfius_clean_response(&auth_resp);
      ulfius_init_response(&auth_resp);
      j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
      ulfius_set_json_body_request(&auth_req, j_body);
      json_decref(j_body);
      res = ulfius_send_http_request(&auth_req, &auth_resp);
      if (res == U_OK && auth_resp.status == 200) {
        y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);
    
        scope_req.http_verb = strdup("PUT");
        scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
        j_body = json_pack("{ss}", "scope", SCOPE_LIST);
        ulfius_set_json_body_request(&scope_req, j_body);
        json_decref(j_body);
        if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
        } else {
          ulfius_init_response(&code_resp);
          user_req.http_verb = strdup("GET");
          user_req.http_url = msprintf("%s/glwd/auth?response_type=code&g_continue&client_id=client1_id&redirect_uri=..%%2f..%%2ftest-oauth2.html%%3fparam%%3dclient1_cb1&state=xyzabcd&scope=%s", SERVER_URI, SCOPE_LIST);
          if (ulfius_send_http_request(&user_req, &code_resp) != U_OK) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "Get code error");
          } else if (o_strstr(u_map_get(code_resp.map_header, "Location"), "code=") != NULL) {
            code = o_strdup(strstr(u_map_get(code_resp.map_header, "Location"), "code=")+strlen("code="));
            if (strchr(code, '&') != NULL) {
              *strchr(code, '&') = '\0';
            }
            do_test = 1;
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "Error, no code given");
          }
          ulfius_clean_response(&code_resp);
        }
        ulfius_clean_response(&scope_resp);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Error auth scheme 95");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error auth scheme 42");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error auth password");
  }
  ulfius_clean_response(&auth_resp);

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_false());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_false());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
  }
  
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&scope_req, j_body);
  json_decref(j_body);
  if (0 && ulfius_send_http_request(&scope_req, NULL) != U_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
  }
  
  url = msprintf("%s/auth/", SERVER_URI);
  run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  o_free(url);
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&scope_req);
  ulfius_clean_request(&register_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
