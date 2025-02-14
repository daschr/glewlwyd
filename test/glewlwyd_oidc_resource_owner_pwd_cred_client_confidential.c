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

#define SERVER_URI "http://localhost:4593/api/oidc"
#define USERNAME "user1"
#define PASSWORD "password"
#define SCOPE_LIST "g_profile scope3"
#define CLIENT "client3_id"
#define CLIENT_PASSWORD "password"

char * code;

START_TEST(test_oidc_resource_owner_pwd_cred_client_confidential_valid)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "password");
  u_map_put(&body, "scope", SCOPE_LIST);
  u_map_put(&body, "username", USERNAME);
  u_map_put(&body, "password", PASSWORD);

  int res = run_simple_test(NULL, "POST", url, CLIENT, CLIENT_PASSWORD, NULL, &body, 200, NULL, "refresh_token", NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_resource_owner_pwd_cred_client_confidential_pwd_invalid)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "password");
  u_map_put(&body, "scope", SCOPE_LIST);
  u_map_put(&body, "username", USERNAME);
  u_map_put(&body, "password", "invalid");

  int res = run_simple_test(NULL, "POST", url, CLIENT, CLIENT_PASSWORD, NULL, &body, 403, NULL, NULL, NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_resource_owner_pwd_cred_client_confidential_user_invalid)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "password");
  u_map_put(&body, "scope", SCOPE_LIST);
  u_map_put(&body, "username", "invalid");
  u_map_put(&body, "password", PASSWORD);

  int res = run_simple_test(NULL, "POST", url, CLIENT, CLIENT_PASSWORD, NULL, &body, 403, NULL, NULL, NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_resource_owner_pwd_cred_client_confidential_client_invalid)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "password");
  u_map_put(&body, "scope", SCOPE_LIST);
  u_map_put(&body, "username", USERNAME);
  u_map_put(&body, "password", PASSWORD);

  int res = run_simple_test(NULL, "POST", url, CLIENT, "invalid", NULL, &body, 400, NULL, NULL, NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_resource_owner_pwd_cred_client_confidential_scope_invalid)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "password");
  u_map_put(&body, "scope", "invalid");
  u_map_put(&body, "username", USERNAME);
  u_map_put(&body, "password", PASSWORD);

  int res = run_simple_test(NULL, "POST", url, CLIENT, CLIENT_PASSWORD, NULL, &body, 403, NULL, NULL, NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_resource_owner_pwd_cred_client_confidential_empty)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "password");

  int res = run_simple_test(NULL, "POST", url, CLIENT, CLIENT_PASSWORD, NULL, &body, 400, NULL, NULL, NULL);
  o_free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd resource owner password credential client confidential");
  tc_core = tcase_create("test_oidc_resource_owner_pwd_cred");
  tcase_add_test(tc_core, test_oidc_resource_owner_pwd_cred_client_confidential_valid);
  tcase_add_test(tc_core, test_oidc_resource_owner_pwd_cred_client_confidential_pwd_invalid);
  tcase_add_test(tc_core, test_oidc_resource_owner_pwd_cred_client_confidential_user_invalid);
  tcase_add_test(tc_core, test_oidc_resource_owner_pwd_cred_client_confidential_client_invalid);
  tcase_add_test(tc_core, test_oidc_resource_owner_pwd_cred_client_confidential_scope_invalid);
  tcase_add_test(tc_core, test_oidc_resource_owner_pwd_cred_client_confidential_empty);
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

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
