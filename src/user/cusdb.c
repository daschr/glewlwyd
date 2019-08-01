/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * PG DB custom auth user module
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

#include <string.h>
#include <jansson.h>
#include <yder.h>
#include "../glewlwyd-common.h"
#include <libpq/pqcomm.h>

#define USER_REPL "{{username}}"
#define HASH_REPL "{{hash}}"
#define BUFSIZE	2048

#define EQ(X) if(strcmp(X,s)==0)

//holds constants

char *user_repl=USER_REPL;
char *hash_repl=HASH_REPL;

//holds db connection
PGConn *pg_connection=NULL;
char **pg_keywords=NULL;
char **pg_values=NULL;



int str_repl(char *buffer, size_t bufsize,char *string, char *tbstring, char *replstring){
	size_t strpos=0;
	size_t bufferpos=0;
	size_t tbstringl=strlen(tbstring);
	while(string[strpos] != '\0' && bufferpos < bufsize){
		if(string[strpos]==*tbstring){
			if(strncmp(string+strpos,tbstring,tbstringl)==0){
				for(size_t i=0;i<strlen(replstring);++i){
					if(bufferpos==bufsize-1)
						return 0;
					buffer[bufferpos++]=replstring[i];
				}
				strpos+=tbstringl;
			}else
				buffer[bufferpos++]=string[strpos++];
		}else
			buffer[bufferpos++]=string[strpos++];
	}
	if(bufferpos>=bufsize)
		return 0;
	buffer[bufferpos]='\0';
	return 1;
}

int in_array(char **a,char *s){
	for(size_t i=0;i<sizeof(a)/sizeof(*a);++i){
		if(strcmp(a[i],s)==0)
			return 1;
	}
	return 0;
}

int map_digest(char *s){
	EQ("MD5")
		return digest_MD5;
	else EQ("SSHA1")
		return digest_SSHA1;
	else EQ("SHA1")
		return digest_SHA1;
	else EQ("SSHA224")
		return digest_SSA224;
	else EQ("SHA224")
		return digest_SHA224;
	else EQ("SSHA256")
		return digest_SSHA256;
	else EQ("SHA256")
		return digest_SHA256;
	else EQ("SSHA384")
		return digest_SSHA384;
	else EQ("SHA384")
		return digest_SHA384;
	else EQ("SHA512")
		return digest_SSHA512;
	else EQ("SHA512")
		return digest_SHA512;
	else EQ("SMD5")
		return digest_SMD5;
	else
		return -1;
	
}

int connect_db(void){
	db_connection=PQconnectdbParams(pg_keywords,pg_values,0);
	
	if(db_connection == NULL)
		return 0;
	if(PQstatus(db_connection) != CONNECTION_OK)
		return 1;
	return 0;
}



json_t * user_module_load(struct config_module * config) {
  UNUSED(config);
  return json_pack("{sisssssss{s{ssso}s{siso}s{ssso}s{ssso}s{ssso}s{ssso}s{ssso}s{ssso}}}",
                   "result",
                   G_OK,
                   "name",
                   "cusdb",
                   "display_name",
                   "Custom Postgres DB backend user module",
                   "description",
                   "Module to check if user is valid in DB",
                   "parameters",
                     "host",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                     "port",
                       "type",
                       "integer",
                       "mandatory",
                       json_true(),
                     "sslmode",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                     "dbname",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                     "user",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                     "password",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                     "hash_type",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
	       	     "sql_cmd",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
		     );
}

int user_module_unload(struct config_module * config) {
  UNUSED(config);
  PQfinish(db_connection);
  for(size_t i=0;i<sizeof(pg_keywords)/sizeof(char*);++i){
  	free(pg_keywords[i]);
	free(pg_values[i]);
  }
  free(pg_keywords);
  free(pg_values);
  return G_OK;
}

json_t * user_module_init(struct config_module * config, int readonly, json_t * j_params, void ** cls) {
  UNUSED(config);
  UNUSED(readonly);
  size_t index = 0;
  json_t * j_element = NULL, * j_return = NULL;
  int ret;
  char *opts[]={"host","dbname","sql_cmd","hash_type"};
  char *db_opts[]={"host","dbname","sslmode","user","password"};
  char emsg[312];
  if(json_is_object(j_params)){
    ret = G_OK;
    for(size_t i=0;i<sizeof(opts)/sizeof(char*);++i){
	if (!json_string_length(json_object_get(j_params, opts[i]))) {
		sprintf(emsg,"user_module_init cusdb - parameter %s is mandatory and must be a non empty string",opts[i]);
		y_log_message(Y_LOG_LEVEL_ERROR, emsg);
		j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", emsg);
		ret = G_ERROR_PARAM;
	}
    }
    
    if(!json_is_integer(json_object_get(j_params,"port")) || json_integer_value(json_object_get(j_params,"port")) <=0){
    		sprintf(emsg,"user_module_init cusdb - parameter port is mandatory and must be a positive number",opts[i]);
		y_log_message(Y_LOG_LEVEL_ERROR, emsg);
		j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", emsg);
		ret = G_ERROR_PARAM;
    }

    if(map_digest(json_string_value(json_object_get(jparams,"hash_type"))) == -1) {
    		sprintf(emsg,"user_module_init cusdb - parameter must be an cipher");
		y_log_message(Y_LOG_LEVEL_ERROR, emsg);
		j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", emsg);
		ret = G_ERROR_PARAM;
    }

    if (ret == G_OK)
	j_return = json_pack("{si}", "result", G_OK);
  }else{
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init cusdb - parameters must be a JSON object");
    ret = G_ERROR_PARAM;
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "parameters must be a JSON object");
  }
  if (ret == G_OK) {
    *cls = json_incref(j_params);
  }
  pg_keywords=malloc(sizeof(char*));
  pg_values=malloc(sizeof(char*));
  size_t cur_size=1;

  for(size_t i=0;i<sizeof(db_opts)/sizeof(char *);++i){
	if(!json_string_length(json_object_get(j_params,db_opts[i])))
		continue;
	if(cur_size==i){
		pg_keywords=realloc(pg_keywords,++cur_size*sizeof(char*));
		pg_values=realloc(pg_keywords,++cur_size*sizeof(char*));
	}
	pg_keywords[i]=strdup(db_opts[i]);
	if(strcmp(pg_keywords[i],"port")==0)
		pg_values[i]=strdup(atoi(json_integer_value(json_object_get(j_params,db_opts[i]))));
	else
		pg_values[i]=strdup(json_string_value(json_object_get(j_params,db_opts[i])));
  }
 
  if(!connect_db()){
	y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init could not connect to database!");
	ret = G_ERROR_PARAM;
	j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "could not connect to database");
  }

  return j_return;
}

int user_module_close(struct config_module * config, void * cls) {
  UNUSED(config);
  json_decref((json_t *)cls);
  return G_OK;
}

size_t user_module_count_total(struct config_module * config, const char * pattern, void * cls) {
  UNUSED(config);
  UNUSED(pattern);
  UNUSED(cls);
  return 0;
}

json_t * user_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls) {
  UNUSED(config);
  UNUSED(pattern);
  UNUSED(offset);
  UNUSED(limit);
  UNUSED(cls);
  return json_pack("{sis[]}", "result", G_OK, "list");
}

json_t * user_module_get(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  return json_pack("{sis{sssOso}}", "result", G_OK, "user", "username", username, "scope", json_object_get((json_t *)cls, "default-scope"), "enabled", json_true());
}

json_t * user_module_get_profile(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  return json_pack("{si}", "result", G_ERROR_NOT_FOUND);
}

json_t * user_module_is_valid(struct config_module * config, const char * username, json_t * j_user, int mode, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(j_user);
  UNUSED(mode);
  UNUSED(cls);
  return json_pack("{si}", "result", G_ERROR_PARAM);
}

int user_module_add(struct config_module * config, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(j_user);
  UNUSED(cls);
  return G_ERROR_PARAM;
}

int user_module_update(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(j_user);
  UNUSED(cls);
  return G_ERROR_PARAM;
}

int user_module_update_profile(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(j_user);
  UNUSED(cls);
  return G_ERROR_PARAM;
}

int user_module_delete(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  return G_ERROR_PARAM;
}

int user_module_check_password(struct config_module * config, const char * username, const char * password, void * cls) {
  UNUSED(config);

  if(PQstatus(db_connection) != CONNECTION_OK)
	if(!db_connect())
		return G_ERROR;

  json_t *conf=(json_t *) cls;
  char *hash=generate_hash(map_digest(json_string_value(json_object_get((json_t *)cls, "hash_type"))),password);
  char cmd_buffer1[BUFSIZE];
  char cmd_buffer2[BUFSIZE];


  if(!str_repl(cmd_buffer1,BUFSIZE,json_string_value(json_object_get(conf,"sql_cmd")),user_repl,username))
  	return G_UNAUTHORIZED;
  if(!str_repl(cmd_buffer2,BUFSIZE,cmd_buffer2,user_repl,username))
  	return G_UNAUTHORIZED;
  PGresult *res=PQexec(db_connection,cmd_buffer2);

  if(PQresultStatus(res) == PGRES_COMMAND_OK)
  	return G_OK;
  else
  	return G_UNAUTHORIZED;
}

int user_module_update_password(struct config_module * config, const char * username, const char * new_password, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(new_password);
  UNUSED(cls);
  return G_ERROR_PARAM;
}
