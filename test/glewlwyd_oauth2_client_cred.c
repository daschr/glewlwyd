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

#define SERVER_URI "http://localhost:4593/api/glwd"
#define CLIENT_ID "client3_id"
#define CLIENT_PASSWORD "password"
#define SCOPE_LIST "scope2 scope3"

struct _u_request user_req;
char * code;

START_TEST(test_oauth2_cred_valid)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", SCOPE_LIST);
  
  int res = run_simple_test(NULL, "POST", url, CLIENT_ID, CLIENT_PASSWORD, NULL, &body, 200, NULL, "access_token", NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oauth2_cred_valid_reduced_scope)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", SCOPE_LIST " scope1");
  
  int res = run_simple_test(NULL, "POST", url, CLIENT_ID, CLIENT_PASSWORD, NULL, &body, 200, NULL, "scope\":\"scope2 scope3\"", NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oauth2_cred_pwd_invalid)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", SCOPE_LIST);
  
  int res = run_simple_test(NULL, "POST", url, CLIENT_ID, "invalid", NULL, &body, 403, NULL, NULL, NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oauth2_cred_client_unauthorized)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", SCOPE_LIST);
  
  int res = run_simple_test(NULL, "POST", url, "client1_id", CLIENT_PASSWORD, NULL, &body, 403, NULL, NULL, NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oauth2_cred_client_invalid)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", SCOPE_LIST);
  
  int res = run_simple_test(NULL, "POST", url, "invalid", CLIENT_PASSWORD, NULL, &body, 403, NULL, NULL, NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oauth2_cred_scope_invalid)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", "scope4");
  
  int res = run_simple_test(NULL, "POST", url, CLIENT_ID, CLIENT_PASSWORD, NULL, &body, 400, NULL, "scope_invalid", NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oauth2_cred_empty)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", SCOPE_LIST);
  
  int res = run_simple_test(NULL, "POST", url, NULL, NULL, NULL, &body, 403, NULL, NULL, NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd client credentials");
  tc_core = tcase_create("test_oauth2_cred");
  tcase_add_test(tc_core, test_oauth2_cred_valid);
  tcase_add_test(tc_core, test_oauth2_cred_valid_reduced_scope);
  tcase_add_test(tc_core, test_oauth2_cred_pwd_invalid);
  tcase_add_test(tc_core, test_oauth2_cred_client_unauthorized);
  tcase_add_test(tc_core, test_oauth2_cred_client_invalid);
  tcase_add_test(tc_core, test_oauth2_cred_scope_invalid);
  tcase_add_test(tc_core, test_oauth2_cred_empty);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  s = glewlwyd_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  ulfius_clean_request(&user_req);

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
