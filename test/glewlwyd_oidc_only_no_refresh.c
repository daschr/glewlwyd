/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define USER_USERNAME "user1"
#define USER_PASSWORD "password"
#define PLUGIN "oidc"
#define PLUGIN_NAME "oidc_claims"
#define SCOPE_LIST "g_profile openid"
#define CLIENT "client1_id"
#define CLIENT_PASSWORD "password"

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_oidc_only_no_refresh_add_plugin)
{
  json_t * j_param = json_pack("{sssssss{sssssssssisisisosososososososo}}",
                                "module",
                                "oidc",
                                "name",
                                PLUGIN_NAME,
                                "display_name",
                                PLUGIN_NAME,
                                "parameters",
                                  "iss",
                                  "https://glewlwyd.tld",
                                  "jwt-type",
                                  "sha",
                                  "jwt-key-size",
                                  "256",
                                  "key",
                                  "secret_" PLUGIN_NAME,
                                  "access-token-duration",
                                  3600,
                                  "refresh-token-duration",
                                  1209600,
                                  "code-duration",
                                  600,
                                  "refresh-token-rolling",
                                  json_true(),
                                  "allow-non-oidc",
                                  json_false(),
                                  "auth-type-code-enabled",
                                  json_true(),
                                  "auth-type-token-enabled",
                                  json_true(),
                                  "auth-type-id-token-enabled",
                                  json_true(),
                                  "auth-type-password-enabled",
                                  json_true(),
                                  "auth-type-client-enabled",
                                  json_true(),
                                  "auth-type-refresh-enabled",
                                  json_false());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_only_no_refresh_id_token_token_ok)
{
  struct _u_response resp;
  struct _u_request req;
  
  ulfius_init_response(&resp);
  ulfius_init_request(&req);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token token&g_continue&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_only_no_refresh_token_error)
{
  struct _u_response resp;
  struct _u_request req;
  
  ulfius_init_response(&resp);
  ulfius_init_request(&req);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=token&g_continue&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=unsupported_response_type"), NULL);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_only_no_refresh_password_error)
{
  char * url = msprintf("%s/%s/token/", SERVER_URI, PLUGIN_NAME);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "password");
  u_map_put(&body, "scope", SCOPE_LIST);
  u_map_put(&body, "username", USER_USERNAME);
  u_map_put(&body, "password", USER_PASSWORD);

  int res = run_simple_test(NULL, "POST", url, NULL, NULL, NULL, &body, 403, NULL, NULL, NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_only_no_refresh_client_error)
{
  char * url = msprintf("%s/%s/token/", SERVER_URI, PLUGIN_NAME);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", SCOPE_LIST);
  
  int res = run_simple_test(NULL, "POST", url, CLIENT, CLIENT_PASSWORD, NULL, &body, 403, NULL, NULL, NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_only_no_refresh_refresh_error)
{
  struct _u_response resp;
  struct _u_request req;
  json_t * j_body;
  char * code, * url;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=code&g_continue&client_id=%s&redirect_uri=../../test-oidc.html?param=client1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code="));
  if (o_strchr(code, '&')) {
    *(o_strchr(code, '&')) = '\0';
  }
  
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  ulfius_init_request(&req);
  req.http_verb = o_strdup("POST");
  req.http_url = msprintf("%s/%s/token/", SERVER_URI, PLUGIN_NAME);
  u_map_put(req.map_post_body, "grant_type", "authorization_code");
  u_map_put(req.map_post_body, "client_id", CLIENT);
  u_map_put(req.map_post_body, "redirect_uri", "../../test-oidc.html?param=client1_cb1");
  u_map_put(req.map_post_body, "code", code);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  
  ck_assert_ptr_ne((j_body = ulfius_get_json_body_response(&resp, NULL)), NULL);  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  ulfius_init_request(&req);
  req.http_verb = o_strdup("POST");
  url = msprintf("%s/%s/token/", SERVER_URI, PLUGIN_NAME);
  u_map_put(req.map_post_body, "grant_type", "refresh_token");
  u_map_put(req.map_post_body, "refresh_token", json_string_value(json_object_get(j_body, "refresh_token")));
  
  ck_assert_int_eq(run_simple_test(&req, "POST", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_body);
  o_free(url);
  o_free(code);
}
END_TEST

START_TEST(test_oidc_only_no_refresh_delete_plugin)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/user/" USER_USERNAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  json_t * j_param = json_pack("{ss ss ss so s[sssss]}", 
                              "username",
                              USER_USERNAME,
                              "name",
                              "Dave Lopper 1",
                              "email",
                              "dev1@glewlwyd",
                              "enabled",
                              json_true(),
                              "scope",
                                "g_profile",
                                "openid",
                                "scope1",
                                "scope2",
                                "scope3");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd profile");
  tc_core = tcase_create("test_oidc_userinfo");
  tcase_add_test(tc_core, test_oidc_only_no_refresh_add_plugin);
  tcase_add_test(tc_core, test_oidc_only_no_refresh_id_token_token_ok);
  tcase_add_test(tc_core, test_oidc_only_no_refresh_token_error);
  tcase_add_test(tc_core, test_oidc_only_no_refresh_password_error);
  tcase_add_test(tc_core, test_oidc_only_no_refresh_client_error);
  tcase_add_test(tc_core, test_oidc_only_no_refresh_refresh_error);
  tcase_add_test(tc_core, test_oidc_only_no_refresh_delete_plugin);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req, scope_req;
  struct _u_response auth_resp, scope_resp;
  int res, do_test = 0;
  json_t * j_body;
  char * cookie;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  ulfius_init_request(&admin_req);
  ulfius_init_request(&user_req);

  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&scope_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_response(&scope_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", ADMIN_USERNAME, "password", ADMIN_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    if (auth_resp.nb_cookies) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Admin %s authenticated", ADMIN_USERNAME);
      cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
      u_map_put(admin_req.map_header, "Cookie", cookie);
      o_free(cookie);
      do_test = 1;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication admin");
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);
  
  if (do_test) {
    // Getting a valid session id for authenticated http requests
    ulfius_init_request(&auth_req);
    ulfius_init_response(&auth_resp);
    auth_req.http_verb = strdup("POST");
    auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
    j_body = json_pack("{ssss}", "username", USER_USERNAME, "password", USER_PASSWORD);
    ulfius_set_json_body_request(&auth_req, j_body);
    json_decref(j_body);
    res = ulfius_send_http_request(&auth_req, &auth_resp);
    if (res == U_OK && auth_resp.status == 200) {
      if (auth_resp.nb_cookies) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "User %s authenticated", USER_USERNAME);
        cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
        u_map_put(scope_req.map_header, "Cookie", cookie);
        u_map_put(user_req.map_header, "Cookie", cookie);
        o_free(cookie);

        scope_req.http_verb = strdup("PUT");
        scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
        j_body = json_pack("{ss}", "scope", SCOPE_LIST);
        ulfius_set_json_body_request(&scope_req, j_body);
        json_decref(j_body);
        if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK || scope_resp.status != 200) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
          do_test = 0;
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope OK");
        }
        ulfius_clean_response(&scope_resp);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication user");
      do_test = 0;
    }
    ulfius_clean_response(&auth_resp);
    ulfius_clean_request(&auth_req);
  }
  
  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&scope_req, j_body);
  json_decref(j_body);
  if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
  }
  
  char * url = msprintf("%s/auth/", SERVER_URI);
  run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  o_free(url);
  
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&scope_req);
  y_close_logs();
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
