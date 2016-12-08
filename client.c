/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * Provides Json Web Tokens (jwt)
 * 
 * client CRUD services
 *
 * Copyright 2016 Nicolas Mora <mail@babelouest.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation;
 * version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "glewlwyd.h"

/**
 * Check client credentials
 * If client_id_header is set, client must be confidential and password must match
 * otherwise client is public
 * Should I use ldap backend for clients too ?
 */
json_t * client_check(struct config_elements * config, const char * client_id, const char * client_id_header, const char * client_password_header, const char * redirect_uri, const int auth_type) {
  json_t * j_result, * j_return;
  int res, is_confidential;
  char * redirect_uri_escaped, * client_id_escaped, * query, * tmp, * password_escaped;
  
  
  if ((client_id != NULL || client_id_header != NULL) && redirect_uri != NULL) {
    if (client_id_header != NULL) {
      client_id_escaped = h_escape_string(config->conn, client_id_header);
      is_confidential = 1;
    } else {
      client_id_escaped = h_escape_string(config->conn, client_id);
      is_confidential = 0;
    }
    
    // I don't want to build a huge j_query since there are 4 tables involved so I'll build my own sql query
    redirect_uri_escaped = h_escape_string(config->conn, redirect_uri);
    query = msprintf("SELECT `%s`.`gc_id` FROM `%s`, `%s`, `%s` WHERE `%s`.`gc_id`=`%s`.`gc_id` AND `%s`.`gc_id`=`%s`.`gc_id`\
                      AND `%s`.`gc_enabled`=1 AND `%s`.`gru_enabled`=1 AND `%s`.`gru_uri`='%s' AND `%s`.`gc_client_id`='%s' \
                      AND `%s`.`got_id`=(SELECT `got_id` FROM `%s` WHERE `got_code`=%d);", 
            GLEWLWYD_TABLE_CLIENT,
            
            GLEWLWYD_TABLE_CLIENT,
            GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE,
            GLEWLWYD_TABLE_REDIRECT_URI,
              
            GLEWLWYD_TABLE_CLIENT,
            GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE,
            
            GLEWLWYD_TABLE_CLIENT,
            GLEWLWYD_TABLE_REDIRECT_URI,
            
            GLEWLWYD_TABLE_CLIENT,
            
            GLEWLWYD_TABLE_REDIRECT_URI,
            
            GLEWLWYD_TABLE_REDIRECT_URI,
            redirect_uri_escaped,
            
            GLEWLWYD_TABLE_CLIENT,
            client_id_escaped,
            
            GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE,
            GLEWLWYD_TABLE_AUTHORIZATION_TYPE,
            auth_type);
    free(redirect_uri_escaped);
    
    if (is_confidential) {
      if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
        password_escaped = h_escape_string(config->conn, client_password_header);
        tmp = msprintf("%s AND `gc_client_password` = PASSWORD('%s')", query, password_escaped);
      } else {
        password_escaped = str2md5(client_password_header, strlen(client_password_header));
        tmp = msprintf("%s AND `gc_client_password` = '%s'", query, password_escaped);
      }
      free(query);
      query = tmp;
    }
    
    res = h_execute_query_json(config->conn, query, &j_result);
    free(query);
    if (res == H_OK) {
      if (json_array_size(j_result) > 0) {
        j_return = json_pack("{siss}", "result", G_OK, "client_id", (is_confidential?client_id_header:client_id));
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_check - Error executing query auth");
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
    free(client_id_escaped);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

/**
 *
 * Check if client credentials are valid
 */
int client_auth(struct config_elements * config, const char * client_id, const char * client_password) {
  json_t * j_query, * j_result;
  int res, to_return;
  char * client_id_escaped, * client_password_escaped, * clause_client_password, * clause_client_authorization_type;
  
  if (client_id != NULL && client_password != NULL) {
    client_id_escaped = h_escape_string(config->conn, client_id);
    clause_client_authorization_type = msprintf("= (SELECT `gc_id` FROM `%s` WHERE `gc_id` = (SELECT `gc_id` FROM `%s` WHERE `gc_client_id` = '%s') and `got_id` = (SELECT `got_id` FROM `%s` WHERE `got_code` = %d))", GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE, GLEWLWYD_TABLE_CLIENT, client_id_escaped, GLEWLWYD_TABLE_AUTHORIZATION_TYPE, GLEWLWYD_AUHORIZATION_TYPE_CLIENT_CREDENTIALS);
    if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
      client_password_escaped = h_escape_string(config->conn, client_password);
      clause_client_password = msprintf("= PASSWORD('%s')", client_password_escaped);
    } else {
      client_password_escaped = str2md5(client_password, strlen(client_password));
      clause_client_password = msprintf("= '%s'", client_password_escaped);
    }
    
    j_query = json_pack("{sss[s]s{sss{ssss}sisis{ssss}}}",
                        "table",
                        GLEWLWYD_TABLE_CLIENT,
                        "columns",
                          "gc_id",
                        "where",
                          "gc_client_id",
                          client_id,
                          "gc_client_password",
                            "operator",
                            "raw",
                            "value",
                            clause_client_password,
                          "gc_enabled",
                          1,
                          "gc_confidential",
                          1,
                          "gc_id",
                            "operator",
                            "raw",
                            "value",
                            clause_client_authorization_type);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    free(clause_client_password);
    free(client_password_escaped);
    free(client_id_escaped);
    free(clause_client_authorization_type);
    if (res == H_OK) {
      to_return = json_array_size(j_result)>0?G_OK:G_ERROR_UNAUTHORIZED;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_auth - Error executing j_query");
      to_return = G_ERROR_DB;
    }
    json_decref(j_result);
  } else {
    to_return = G_ERROR_UNAUTHORIZED;
  }
  return to_return;
}

/**
 *
 * Check if user has allowed scope for client_id
 *
 */
int auth_check_client_user_scope(struct config_elements * config, const char * client_id, const char * username, const char * scope_list) {
  json_t * j_query, * j_result;
  int res, nb_scope = 0;
  char * scope, * escaped_scope, * escaped_scope_list = NULL, * save_scope_list, * saveptr, * tmp;
  char * client_id_escaped, * client_clause, * scope_clause;
  
  save_scope_list = strdup(scope_list);
  scope = strtok_r(save_scope_list, " ", &saveptr);
  while (scope != NULL) {
    nb_scope++;
    escaped_scope = h_escape_string(config->conn, scope);
    if (escaped_scope_list == NULL)  {
      escaped_scope_list = msprintf("'%s'", escaped_scope);
    } else {
      tmp = msprintf("%s,'%s'", escaped_scope_list, escaped_scope);
      free(escaped_scope_list);
      escaped_scope_list = tmp;
    }
    free(escaped_scope);
    scope = strtok_r(NULL, " ", &saveptr);
  }
  free(save_scope_list);
  
  client_id_escaped = h_escape_string(config->conn, client_id);
  client_clause = msprintf("= (SELECT `gc_id` FROM `%s` WHERE `gc_client_id`='%s')", GLEWLWYD_TABLE_CLIENT, client_id_escaped);
  scope_clause = msprintf("IN (SELECT `gs_id` FROM `%s` WHERE `gs_name` IN (%s))", GLEWLWYD_TABLE_SCOPE, escaped_scope_list);
  j_query = json_pack("{sss[s]s{sss{ssss}s{ssss}}}",
            "table",
            GLEWLWYD_TABLE_CLIENT_USER_SCOPE,
            "columns",
              "gcus_id",
            "where",
              "gco_username",
              username,
              "gc_id",
                "operator",
                "raw",
                "value",
                client_clause,
              "gs_id",
                "operator",
                "raw",
                "value",
                scope_clause
            );
  free(client_id_escaped);
  free(client_clause);
  free(scope_clause);
  free(escaped_scope_list);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    nb_scope -= json_array_size(j_result);
    json_decref(j_result);
    return (nb_scope==0?G_OK:G_ERROR_UNAUTHORIZED);
  } else {
    return G_ERROR_DB;
  }
}

json_t * auth_check_client_scope(struct config_elements * config, const char * client_id, const char * scope_list) {
  json_t * j_query, * j_result, * scope_list_allowed, * j_value;
  int res;
  char * scope, * scope_escaped, * saveptr, * scope_list_escaped = NULL, * scope_list_save = nstrdup(scope_list), * client_id_escaped = h_escape_string(config->conn, client_id), * scope_list_join;
  char * where_clause, * tmp;
  size_t index;
  
  if (scope_list == NULL || client_id_escaped == NULL) {
    scope_list_allowed = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (scope_list_save != NULL && client_id_escaped != NULL) {
    scope = strtok_r(scope_list_save, " ", &saveptr);
    while (scope != NULL) {
      scope_escaped = h_escape_string(config->conn, scope);
      if (scope_list_escaped != NULL) {
        tmp = msprintf("%s,'%s'", scope_list_escaped, scope_escaped);
        free(scope_list_escaped);
        scope_list_escaped = tmp;
      } else {
        scope_list_escaped = msprintf("'%s'", scope_escaped);
      }
      free(scope_escaped);
      scope = strtok_r(NULL, " ", &saveptr);
    }
    free(scope_list_save);
    where_clause = msprintf("IN (SELECT gs_id FROM %s WHERE gc_id = (SELECT gc_id FROM %s WHERE gc_client_id='%s') AND gs_id IN (SELECT gs_id FROM %s WHERE gs_name IN (%s)))", GLEWLWYD_TABLE_CLIENT_SCOPE, GLEWLWYD_TABLE_CLIENT, client_id_escaped, GLEWLWYD_TABLE_SCOPE, scope_list_escaped);
    j_query = json_pack("{sss[s]s{s{ssss}}}",
              "table",
              GLEWLWYD_TABLE_SCOPE,
              "columns",
                "gs_name",
              "where",
                "gs_id",
                  "operator",
                  "raw",
                  "value",
                  where_clause);
    free(scope_list_escaped);
    free(where_clause);
    if (j_query != NULL) {
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result) > 0) {
          scope_list_join = strdup("");
          json_array_foreach(j_result, index, j_value) {
            if (nstrlen(scope_list_join) > 0) {
              tmp = msprintf("%s %s", scope_list_join, json_string_value(json_object_get(j_value, "gs_name")));
              free(scope_list_join);
              scope_list_join = tmp;
            } else {
              free(scope_list_join);
              scope_list_join = strdup(json_string_value(json_object_get(j_value, "gs_name")));
            }
          }
          scope_list_allowed = json_pack("{siss}", "result", G_OK, "scope", scope_list_join);
          free(scope_list_join);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_client_scope - Error client_id '%s' with scope %s", client_id, scope_list);
          scope_list_allowed = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_client_scope - Error executing sql query");
        scope_list_allowed = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_client_scope - Error allocating resources for j_query");
      scope_list_allowed = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_client_scope - Error allocating resources for scope_list_save %s or client_id_escaped %s or scope_list_escaped %s", scope_list_save, client_id_escaped, scope_list_escaped);
    scope_list_allowed = json_pack("{si}", "result", G_ERROR);
  }
  free(client_id_escaped);
  return scope_list_allowed;
}
