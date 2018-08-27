/*
 * bjornwennberg71@gmail.com
 * 
 * built upon be-openam.c
 *
 */

#ifdef BE_OPENAM
#include "backends.h"
#include "be-openam.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"
#include "hash.h"
#include "log.h"
#include "envs.h"
#include <curl/curl.h>
#include "userdata.h"
#include <json-c/json.h>

//////////////////////////////////////////////////////////////////////////////
//
// Holds content from a rest api
//
typedef struct MemoryStruct
{
  char *memory;
  size_t size;
} MemoryStruct;

//
// cb for curl
//
static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL)
  {
    /* out of memory! */ 
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
 
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}


//////////////////////////////////////////////////////////////////////////////
//
// regular username/password auth
static
int
openam_post_authenticate_username_password(void *handle, char *uri, const char *clientid, const char *username, const char *password, const char *topic, int acc, int method, char *tokenid)
{
  //struct openam_backend *conf = (struct openam_backend *)handle;
  CURL *curl;
  struct curl_slist *headerlist = NULL;
  int re;
  int respCode = 0;
  int ok = BACKEND_DEFER;
  char *url;
  struct MemoryStruct chunk;


  if (!tokenid)
  {
    return BACKEND_ERROR;
  }
  
  if (username == NULL)
  {
    return BACKEND_DEFER;
  }
  if ((curl = curl_easy_init()) == NULL)
  {
    _fatal("create curl_easy_handle fails");
    return BACKEND_ERROR;
  }

  chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */ 
  chunk.size = 0;    /* no data at this point */ 
  
  clientid = (clientid && *clientid) ? clientid : "";
  password = (password && *password) ? password : "";
  topic    = (topic    && *topic)    ? topic    : "";

  char
    azValue[500];

  sprintf(azValue, "X-OpenAM-Username: %s", username);
  headerlist = curl_slist_append(headerlist, azValue);

  sprintf(azValue, "X-OpenAM-Password: %s", password);
  headerlist = curl_slist_append(headerlist, azValue);

  sprintf(azValue, "Connection: close\r\n");
  headerlist = curl_slist_append(headerlist, azValue);
  
  url = strdup(uri);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
  curl_easy_setopt(curl, CURLOPT_POST, 1L); 
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist); 

  re = curl_easy_perform(curl);
  
  if (re == CURLE_OK)
  {
    re = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &respCode);
    if (re == CURLE_OK && respCode >= 200 && respCode < 300)
    {
      ok = BACKEND_ALLOW;
    }
    else if (re == CURLE_OK && respCode >= 500)
    {
      ok = BACKEND_ERROR;
    }
    else
    {
          //_log(LOG_NOTICE, "openam auth fail re=%d respCode=%d", re, respCode);
    }
  }
  else
  {
    _log(LOG_DEBUG, "openam req fail url=%s re=%s", url, curl_easy_strerror(re));
    ok = BACKEND_ERROR;
  }


  if (ok == BACKEND_ALLOW )
  {
    ok = BACKEND_DEFER;

        // json should look like this for an auth:
        // {"tokenId":"3v7Vmpa_huK6PyRkkpoRkdW92dY.*AAJTSQACMDEAAlNLABxLbWRNa3NYUmNDQmZwc0JMZVhkZ09HYkVKRUk9AAJTMQAA*","successUrl":"/openam/console","realm":"/edgecontroller"}
    
        // parse json
    struct json_object *jobj;
    jobj = json_tokener_parse(chunk.memory);
    
    struct json_object
      *token_id,
      *success_url,
      *realm;
    
    if (json_object_object_get_ex(jobj, "tokenId",   &token_id) &&
        json_object_object_get_ex(jobj, "successUrl", &success_url) &&
        json_object_object_get_ex(jobj, "realm",      &realm))
    {
      const char
        *pzTokenID = json_object_to_json_string(token_id);

      
      while(pzTokenID && *pzTokenID && *pzTokenID == '"') pzTokenID++;

      strcpy(tokenid, pzTokenID);
      int nlen = strlen(tokenid);
      while(tokenid[nlen -1] == '"')
      {
        tokenid[nlen - 1] = 0;
        nlen--;
      }

      ok = BACKEND_ALLOW;
          /* printf("TOKEN_ID = %s\n", pzTokenID); fflush(stdout); */

    }
    else
    {
      ok = BACKEND_ERROR;
    }

  }

  curl_easy_cleanup(curl);
  curl_slist_free_all (headerlist);
  free(url);

  free(chunk.memory);
    return (ok);
}

//////////////////////////////////////////////////////////////////////////////
//
//
// if username == “_authn_openid_” then the <password> is and OpenID Token
//
// curl -X POST 
//  'openam://myiot-am.forgerocklabs.net:8080/openam/oauth2/idtokeninfo?realm=edgecontroller' 
//  -H 'Authorization: Basic ZWRnZWNvbnRyb2xsZXI6cGFzc3cwcmQy'          
//  -H 'Cache-Control: no-cache'                                        
//  -H 'Content-Type: application/x-www-form-urlencoded'                
//  -d 'id_token=<password>'

//auth_opt_openam_client_id      egdecontroller
//auth_opt_openam_client_secret  password2
//
// Basic Authentication: base64(auth_opt_client_id:auth_opt_client_secret)
//
static
int
openam_post_authenticate_idtoken(void *handle, char *uri, const char *clientid, const char *username, const char *password, const char *topic, int acc, int method, char *token_response)
{
  struct openam_backend *conf = (struct openam_backend *)handle;
  CURL *curl;
  struct curl_slist *headerlist = NULL;
  int re;
  int respCode = 0;
  int ok = BACKEND_DEFER;
  char *url;
  struct MemoryStruct chunk;

  if (username == NULL)
  {
    return BACKEND_DEFER;
  }
  

  clientid = (clientid && *clientid) ? clientid : "";
  password = (password && *password) ? password : "";
  topic    = (topic    && *topic)    ? topic    : "";

  if ((curl = curl_easy_init()) == NULL)
  {
    _fatal("create curl_easy_handle fails");
    return BACKEND_ERROR;
  }

  chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */ 
  chunk.size = 0;    /* no data at this point */ 
  
  char
    azValue[500];
  {
    char
      *pzAuthenticationBasics = NULL;
    sprintf(azValue, "%s:%s", conf->auth_opt_openam_client_id, conf->auth_opt_openam_client_secret);
    base64_encode(azValue, strlen(azValue), &pzAuthenticationBasics);
    
    sprintf(azValue, "Authorization: Basic %s", pzAuthenticationBasics);
    headerlist = curl_slist_append(headerlist, azValue);
    
    free(pzAuthenticationBasics);
    pzAuthenticationBasics = NULL;
  }
  
  headerlist = curl_slist_append(headerlist, "Cache-control: no-cache");
  headerlist = curl_slist_append(headerlist, "Content-type: application/x-www-form-urlencoded");

  url = strdup(uri);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  char
    azValue2[10000];
  
  sprintf(azValue2, "id_token=%s", password);
  curl_easy_setopt(curl, CURLOPT_POST, 1L); 
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, azValue2);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist); 

  
  re = curl_easy_perform(curl);
  
  if (re == CURLE_OK)
  {
    re = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &respCode);
    if (re == CURLE_OK && respCode >= 200 && respCode < 300)
    {
      ok = BACKEND_ALLOW;
    }
    else if (re == CURLE_OK && respCode >= 500)
    {
      ok = BACKEND_ERROR;
    }
    else
    {
          //_log(LOG_NOTICE, "openam auth fail re=%d respCode=%d", re, respCode);
    }
  }
  else
  {
    _log(LOG_DEBUG, "openam req fail url=%s re=%s", url, curl_easy_strerror(re));
    ok = BACKEND_ERROR;
  }


  if (ok == BACKEND_ALLOW )
  {
    ok = BACKEND_DEFER;

        // json should look like this for an auth:
        // {"tokenId":"3v7Vmpa_huK6PyRkkpoRkdW92dY.*AAJTSQACMDEAAlNLABxLbWRNa3NYUmNDQmZwc0JMZVhkZ09HYkVKRUk9AAJTMQAA*","successUrl":"/openam/console","realm":"/edgecontroller"}

    strcpy(token_response, chunk.memory);
    ok = BACKEND_ALLOW;
  }

  curl_easy_cleanup(curl);
  curl_slist_free_all (headerlist);
  free(url);
  free(chunk.memory);
  
  return (ok);
}

//////////////////////////////////////////////////////////////////////////////
//
// using access token
//
static
int
openam_post_authenticate_accesstoken(void *handle, char *uri, const char *clientid, const char *username, const char *password, const char *topic, int acc, int method, char *token_response)
{
  CURL *curl;
  struct curl_slist *headerlist = NULL;
  int re;
  int respCode = 0;
  int ok = BACKEND_DEFER;
  char *url;
  struct MemoryStruct chunk;

  if (!token_response)
  {
    return -1;
  }
  
  
      /* char *data; */

  if (username == NULL)
  {
    return BACKEND_DEFER;
  }

  clientid = (clientid && *clientid) ? clientid : "";
  password = (password && *password) ? password : "";
  topic    = (topic    && *topic)    ? topic    : "";

  if ((curl = curl_easy_init()) == NULL)
  {
    _fatal("create curl_easy_handle fails");
    return BACKEND_ERROR;
  }
  char
    azValue[5000];

  chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */ 
  chunk.size = 0;    /* no data at this point */ 
  
  sprintf(azValue, "Authorization: Bearer %s", password);
  headerlist = curl_slist_append(headerlist, azValue);
  headerlist = curl_slist_append(headerlist, "Cache-control: no-cache\r\n");

  url = strdup(uri);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
  curl_easy_setopt(curl, CURLOPT_POST, 1L); 
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist); 

  
  re = curl_easy_perform(curl);
  
  if (re == CURLE_OK)
  {
    re = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &respCode);
    if (re == CURLE_OK && respCode >= 200 && respCode < 300)
    {
      ok = BACKEND_ALLOW;
    }
    else if (re == CURLE_OK && respCode >= 500)
    {
      ok = BACKEND_ERROR;
    }
    else
    {
          //_log(LOG_NOTICE, "openam auth fail re=%d respCode=%d", re, respCode);
    }
  }
  else
  {
    _log(LOG_DEBUG, "openam req fail url=%s re=%s", url, curl_easy_strerror(re));
    ok = BACKEND_ERROR;
  }


  if (ok == BACKEND_ALLOW )
  {
    strcpy(token_response, chunk.memory);
  }

  curl_easy_cleanup(curl);
  curl_slist_free_all (headerlist);
  free(url);
  free(chunk.memory);
  
  return (ok);
}

//////////////////////////////////////////////////////////////////////////////
//
// authorize (acl)
//
static
int
openam_post_authorize(void *handle, const char *uri, const char *clientid, const char *username, const char *password, const char *topic, int acc, int method, char *tokenid, char *ssoToken)
{
  struct openam_backend *conf = (struct openam_backend *)handle;
  CURL *curl;
  struct curl_slist *headerlist = NULL;
  int re;
  int respCode = 0;
  int ok = BACKEND_DEFER;
  char *url;
  struct MemoryStruct chunk;

  if (!tokenid)
  {
    return BACKEND_ERROR;
  }
      /* char *data; */

  if (username == NULL)
  {
    return BACKEND_DEFER;
  }

  if ((curl = curl_easy_init()) == NULL)
  {
    _fatal("create curl_easy_handle fails");
    return BACKEND_ERROR;
  }

  clientid = (clientid && *clientid) ? clientid : "";
  password = (password && *password) ? password : "";
  topic    = (topic    && *topic)    ? topic    : "";
  
  chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */ 
  chunk.size = 0;    /* no data at this point */ 
  

      // username+password:
      // idtoken:
      //      "claims" : {
      //  	"sub" : “username"
      //  }
      // accesstoken:
      // 

  const char 
    *pzUsernamePasswordContent = \
"{                             \n"
"  \"resources\" : [           \n"
"  \"mqtt+topic://%s\"         \n"
"  ],                          \n"
"  \"application\": \"%s\",    \n"
"  \"subject\": {              \n"
"    \"ssoToken\": \"%s\"      \n"
"  }                           \n"
"}";

  const char 
    *pzTokenContent = \
"{                             \n"
"  \"resources\" : [           \n"
"  \"mqtt+topic://%s\"         \n"
"  ],                          \n"
"  \"application\": \"%s\",    \n"
"  \"subject\": {              \n"
"    \"claims\": %s            \n"
"  } \n"
"}";
  

  char
    * pzContent = NULL;

  if (method == 0)
  {
    pzContent = malloc(strlen(pzUsernamePasswordContent) + strlen(topic) + strlen(conf->auth_opt_openam_application) + strlen(tokenid) + 10);
    
    sprintf(pzContent, pzUsernamePasswordContent, topic, conf->auth_opt_openam_application, tokenid);
  }
  else
  {
    pzContent = malloc(strlen(pzTokenContent) + strlen(topic) + strlen(conf->auth_opt_openam_application) + strlen(tokenid) + 10);
    sprintf(pzContent, pzTokenContent, topic, conf->auth_opt_openam_application, tokenid);
  }

  char
    * pzValue = NULL;
  if (method == 0)
  {
    pzValue = malloc(strlen(conf->auth_opt_openam_cookiename) + strlen(tokenid) + 100);
    sprintf(pzValue, "%s: %s", conf->auth_opt_openam_cookiename, tokenid);
    headerlist = curl_slist_append(headerlist, pzValue);
  }
  else 
  {
    pzValue = malloc(strlen(conf->auth_opt_openam_cookiename) + strlen(ssoToken) + 100);
    sprintf(pzValue, "%s: %s", conf->auth_opt_openam_cookiename, ssoToken);
    headerlist = curl_slist_append(headerlist, pzValue);
  }
  
  sprintf(pzValue, "Content-Type:application/json");
  headerlist = curl_slist_append(headerlist, pzValue);
  
  url = strdup(uri);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
  curl_easy_setopt(curl, CURLOPT_POST, 1L); 
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, pzContent);

  
  re = curl_easy_perform(curl);
  
  if (re == CURLE_OK)
  {
    re = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &respCode);
    if (re == CURLE_OK && respCode >= 200 && respCode < 300)
    {
      ok = BACKEND_ALLOW;
    }
    else if (re == CURLE_OK && respCode >= 500)
    {
      ok = BACKEND_ERROR;
    }
    else
    {
          //_log(LOG_NOTICE, "openam auth fail re=%d respCode=%d", re, respCode);
    }
  }
  else
  {
    _log(LOG_DEBUG, "openam req fail url=%s re=%s", url, curl_easy_strerror(re));
    ok = BACKEND_ERROR;
  }


  if (ok == BACKEND_ALLOW )
  {
    ok = BACKEND_DEFER;
    
        // json should look like this for an auth:
        // {"tokenId":"3v7Vmpa_huK6PyRkkpoRkdW92dY.*AAJTSQACMDEAAlNLABxLbWRNa3NYUmNDQmZwc0JMZVhkZ09HYkVKRUk9AAJTMQAA*","successUrl":"/openam/console","realm":"/edgecontroller"}
    
        // parse json
    struct json_object *jobj;
    jobj = json_tokener_parse(chunk.memory);
    
    struct json_object
      *advices,
      *ttl,
      *resource,
      *actions,
      *attributes;

        // there is only one element in the response array since we only asked for one topic
    struct json_object
      *elem0 = 	json_object_array_get_idx(jobj, 0);

    
    if (json_object_object_get_ex(elem0, "advices",   &advices) &&
        json_object_object_get_ex(elem0, "ttl",       &ttl) &&
        json_object_object_get_ex(elem0, "resource",  &resource) &&
        json_object_object_get_ex(elem0, "actions",   &actions)  &&
        json_object_object_get_ex(elem0, "attributes",&attributes)
        )
    {
      struct json_object
        *subscribe,
        *publish;

          // publish
      if (acc == 2 && json_object_object_get_ex(actions, "PUBLISH", &publish))
      {
        bool
          value = json_object_get_boolean(publish);
        if (value)
        {
              // allowed to publish
          ok = BACKEND_ALLOW;
        }
      }
      else if ((acc == 1 ) && json_object_object_get_ex(actions, "SUBSCRIBE", &subscribe))
      {
        bool
          value = json_object_get_boolean(subscribe);
        if (value)
        {
              // allowed to publish
          ok = BACKEND_ALLOW;
        }
        
      }
      
    }
    else
    {
      ok = BACKEND_ERROR;
    }

  }

  curl_easy_cleanup(curl);
  curl_slist_free_all (headerlist);
  free(url);
  free(chunk.memory);
  free(pzContent);
  free(pzValue);
  
  return (ok);
}

//////////////////////////////////////////////////////////////////////////////
//
// init the plugin
// read and parse parameters from mosquitto.conf
// Fill in conf struct
//
void *
be_openam_init()
{
  /* printf("*** %s\n", __FUNCTION__); */
  /* fflush(stdout); */
  
  struct openam_backend *conf;
//  char *hostname;
//  char *getuser_uri;
//  char *superuser_uri;
//  char *aclcheck_uri;
  char *auth_opt_openam_host; // myiot-am.forgerocklabs.net
  char *auth_opt_openam_port; // 8080
  char *auth_opt_openam_path; // /openam
  char *auth_opt_openam_realm; // /edgecontroller
  char *auth_opt_openam_cookiename; // iPlanetDirectoryPro
  char *auth_opt_openam_agent_realm; //      /
  char *auth_opt_openam_agent_user; //      amadmin
  char *auth_opt_openam_agent_password; //  Forger0ck!
  char *auth_opt_openam_client_id; //      egdecontroller
  char *auth_opt_openam_client_secret; //  password2
  char *auth_opt_openam_application; //  things

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    _fatal("init curl fail");
    return (NULL);
  }

  /* if ((hostname = p_stab("openam_ip")) == NULL && (hostname = p_stab("openam_hostname")) == NULL) { */
  /*   _fatal("Mandatory parameter: one of either `openam_ip' or `openam_hostname' required"); */
  /*   return (NULL); */
  /* } */
  
  /* if ((getuser_uri = p_stab("openam_getuser_uri")) == NULL) { */
  /*   _fatal("Mandatory parameter `openam_getuser_uri' missing"); */
  /*   return (NULL); */
  /* } */
  /* if ((superuser_uri = p_stab("openam_superuser_uri")) == NULL) { */
  /*   _fatal("Mandatory parameter `openam_superuser_uri' missing"); */
  /*   return (NULL); */
  /* } */
  /* if ((aclcheck_uri = p_stab("openam_aclcheck_uri")) == NULL) { */
  /*   _fatal("Mandatory parameter `openam_aclcheck_uri' missing"); */
  /*   return (NULL); */
  /* } */

  auth_opt_openam_host = p_stab("openam_host");
  if (!auth_opt_openam_host)
  {
    _fatal("Mandatory parameter 'auth_opt_openam_host' missing");
    return NULL;
  }
  
  auth_opt_openam_port = p_stab("openam_port");
  if (!auth_opt_openam_port)
  {
    _fatal("Mandatory parameter 'auth_opt_openam_port' missing");
    return NULL;
  }
  
  auth_opt_openam_path = p_stab("openam_path");
  if (!auth_opt_openam_path)
  {
    _fatal("Mandatory parameter 'auth_opt_openam_path' missing");
    return NULL;
  }
  
  auth_opt_openam_realm = p_stab("openam_realm");
  if (!auth_opt_openam_realm)
  {
    _fatal("Mandatory parameter 'auth_opt_openam_realm' missing");
    return NULL;
  }
  
  auth_opt_openam_cookiename = p_stab("openam_cookiename");
  if (!auth_opt_openam_cookiename)
  {
    _fatal("Mandatory parameter 'auth_opt_openam_cookiename' missing");
    return NULL;
  }
  
  auth_opt_openam_agent_realm = p_stab("openam_agent_realm");
  if (!auth_opt_openam_agent_realm)
  {
    _fatal("Mandatory parameter 'auth_opt_openam_agent' missing");
    return NULL;
  }

  auth_opt_openam_agent_user = p_stab("openam_agent_user");
  if (!auth_opt_openam_agent_user)
  {
    _fatal("Mandatory parameter 'auth_opt_openam_agent' missing");
    return NULL;
  }
  
  auth_opt_openam_agent_password = p_stab("openam_agent_password");
  if (!auth_opt_openam_agent_password)
  {
    _fatal("Mandatory parameter 'auth_opt_openam_agent' missing");
    return NULL;
  }
  
  auth_opt_openam_client_id = p_stab("openam_client_id");
  if (!auth_opt_openam_client_id)
  {
    _fatal("Mandatory parameter 'auth_opt_openam_client' missing");
    return NULL;
  }
  
  auth_opt_openam_client_secret = p_stab("openam_client_secret");
  if (!auth_opt_openam_client_secret)
  {
    _fatal("Mandatory parameter 'auth_opt_openam_client' missing");
    return NULL;
  }
  
  auth_opt_openam_application = p_stab("openam_application");
  if (!auth_opt_openam_application)
  {
    _fatal("Mandatory parameter 'auth_opt_openam_application' missing");
    return NULL;
  }
  

  conf = (struct openam_backend *)malloc(sizeof(struct openam_backend));
      //conf->hostname = hostname;
  conf->port = p_stab("openam_port") == NULL ? 80 : atoi(p_stab("openam_port"));
  if (p_stab("openam_hostname") != NULL) {
    conf->hostheader = (char *)malloc(128);
    sprintf(conf->hostheader, "Host: %s", p_stab("openam_hostname"));
  }
  else
  {
    conf->hostheader = NULL;
  }
      //conf->getuser_uri = getuser_uri;
      //conf->superuser_uri = superuser_uri;
      //conf->aclcheck_uri = aclcheck_uri;

  conf->getuser_envs = p_stab("openam_getuser_params");
//  conf->superuser_envs = p_stab("openam_superuser_params");
  conf->aclcheck_envs = p_stab("openam_aclcheck_params");
  if(p_stab("openam_basic_auth_key")!= NULL){
    conf->basic_auth = (char *)malloc( strlen("Authorization: Basic %s") + strlen(p_stab("openam_basic_auth_key")));
    sprintf(conf->basic_auth, "Authorization: Basic %s",p_stab("openam_basic_auth_key"));
  }
  else
  {
    conf->basic_auth = NULL;
  }


  if (p_stab("openam_with_tls") != NULL)
  {
    conf->with_tls = p_stab("openam_with_tls");
  }
  else
  {
    conf->with_tls = "false";
  }
  if (strcmp(conf->with_tls, "true") == 0)
  {
    conf->is_tls = 1;
  }
  else
  {
    conf->is_tls = 0;
  }
  
  conf->retry_count = p_stab("openam_retry_count") == NULL ? 3 : atoi(p_stab("openam_retry_count"));

  conf->auth_opt_openam_host          = auth_opt_openam_host;
  conf->auth_opt_openam_port          = atoi(auth_opt_openam_port);
  conf->auth_opt_openam_path          = auth_opt_openam_path;
  conf->auth_opt_openam_realm         = auth_opt_openam_realm;
  conf->auth_opt_openam_cookiename    = auth_opt_openam_cookiename;
  conf->auth_opt_openam_agent_realm   = auth_opt_openam_agent_realm;
  conf->auth_opt_openam_agent_user    = auth_opt_openam_agent_user;
  conf->auth_opt_openam_agent_password= auth_opt_openam_agent_password;
  conf->auth_opt_openam_client_id     = auth_opt_openam_client_id;
  conf->auth_opt_openam_client_secret = auth_opt_openam_client_secret;
  conf->auth_opt_openam_application   = auth_opt_openam_application;


      //
      // authenticate_uri
      // openam://myiot-am.forgerocklabs.net:8080/openam/json/authenticate?realm=edgecontroller
      // 
  char
    *p = malloc(5000);


  sprintf(p, "%s://%s:%d%s/json/authenticate?realm=%s",
          (conf->is_tls ? "https" : "http"),
          conf->auth_opt_openam_host,
          conf->auth_opt_openam_port,
          conf->auth_opt_openam_path,
          conf->auth_opt_openam_realm);
  printf("URI = %s\n", p);
  
  conf->openam_authenticate_uri = p;


      //
      // authenticate_agent_uri
      // openam://myiot-am.forgerocklabs.net:8080/openam/json/authenticate?realm=edgecontroller
      // 
  
  p = malloc(5000);
  sprintf(p, "%s://%s:%d%s/json/authenticate?realm=%s",
          (conf->is_tls ? "https" : "http"),
          conf->auth_opt_openam_host,
          conf->auth_opt_openam_port,
          conf->auth_opt_openam_path,
          conf->auth_opt_openam_agent_realm);
  printf("URI = %s\n", p);
  
  conf->openam_authenticate_agent_uri = p;

      //
      // authorize_client_uri
      // openam://myiot-am.forgerocklabs.net:8080/openam/json/policies?_action=evaluate&realm=edgecontroller
      // 
  
  p = malloc(5000);
  sprintf(p, "%s://%s:%d%s/json/policies?_action=evaluate&realm=%s",
          (conf->is_tls ? "https" : "http"),
          conf->auth_opt_openam_host,
          conf->auth_opt_openam_port,
          conf->auth_opt_openam_path,
          conf->auth_opt_openam_realm);
  printf("URI = %s\n", p);
  
  conf->openam_authorize_user_uri = p;

      //
      // authenticate_idtoken
      // openam://myiot-am.forgerocklabs.net:8080/openam/oauth2/idtokeninfo?realm=edgecontroller' 
      // 
  
  p = malloc(5000);
  sprintf(p, "%s://%s:%d%s/oauth2/idtokeninfo?realm=%s",
          (conf->is_tls ? "https" : "http"),
          conf->auth_opt_openam_host,
          conf->auth_opt_openam_port,
          conf->auth_opt_openam_path,
          conf->auth_opt_openam_realm);
  printf("URI = %s\n", p);
  
  conf->openam_authenticate_idtoken = p;

      //
      // authenticate_accesstoken
      // openam://myiot-am.forgerocklabs.net:8080/openam/oauth2/userinfo?realm=edgecontroller' 
      // 
  
  p = malloc(5000);
  sprintf(p, "%s://%s:%d%s/oauth2/userinfo?realm=%s",
          (conf->is_tls ? "https" : "http"),
          conf->auth_opt_openam_host,
          conf->auth_opt_openam_port,
          conf->auth_opt_openam_path,
          conf->auth_opt_openam_realm);
  printf("URI = %s\n", p);
  
  conf->openam_authenticate_accesstoken = p;
  
  _log(LOG_DEBUG, "with_tls=%s", conf->with_tls);
//  _log(LOG_DEBUG, "getuser_uri=%s", getuser_uri);
//  _log(LOG_DEBUG, "superuser_uri=%s", superuser_uri);
//  _log(LOG_DEBUG, "aclcheck_uri=%s", aclcheck_uri);
//  _log(LOG_DEBUG, "getuser_params=%s", conf->getuser_envs);
//  _log(LOG_DEBUG, "superuser_params=%s", conf->superuser_envs);
  _log(LOG_DEBUG, "aclcheck_paramsi=%s", conf->aclcheck_envs);
  _log(LOG_DEBUG, "retry_count=%d", conf->retry_count);

  printf("auth_opt_openam_host = %s\n", conf->auth_opt_openam_host);
  printf("auth_opt_openam_port = %d\n", conf->auth_opt_openam_port);
  printf("auth_opt_openam_path = %s\n", conf->auth_opt_openam_path);
  printf("auth_opt_openam_realm = %s\n", conf->auth_opt_openam_realm);
  printf("auth_opt_openam_cookiename = %s\n", conf->auth_opt_openam_cookiename);
  printf("auth_opt_openam_agent_user = %s\n", conf->auth_opt_openam_agent_user);
  printf("auth_opt_openam_agent_password = %s\n", conf->auth_opt_openam_agent_password);
  printf("auth_opt_openam_client_id = %s\n", conf->auth_opt_openam_client_id);
  printf("auth_opt_openam_client_secret = %s\n", conf->auth_opt_openam_client_secret);
  printf("auth_opt_openam_application = %s\n", conf->auth_opt_openam_application);

  return (conf);
}

//////////////////////////////////////////////////////////////////////////////
//
// deallocate all
void
be_openam_destroy(void *handle)
{
  /* printf("*** %s\n", __FUNCTION__); */
  /* fflush(stdout); */

  struct openam_backend *conf = (struct openam_backend *)handle;

  if (conf)
  {
    curl_global_cleanup();
    free(conf);
  }
}

//////////////////////////////////////////////////////////////////////////////
//
// authn part
//
int
be_openam_getuser(void *handle, const char *username, const char *password, char **phash)
{
  struct openam_backend *conf = (struct openam_backend *)handle;
  int re, try;

  printf("be_openam_getuser\n");
  if (username == NULL)
  {
    return BACKEND_DEFER;
  }

  
  

  
  re = BACKEND_ERROR;
  try = 0;

  char
    azTokenID[5000];
  azTokenID[0] = 0;


  
  while (re == BACKEND_ERROR && try <= conf->retry_count)
  {
    try++;
    
    if (strcmp(username, "_authn_openid_") == 0)
    {
      re = openam_post_authenticate_idtoken(handle, conf->openam_authenticate_idtoken, NULL, username, password, NULL, -1, METHOD_GETUSER, azTokenID);
    }
    else if (strcmp(username, "_authn_access_token_") == 0)
    {
      re = openam_post_authenticate_accesstoken(handle, conf->openam_authenticate_accesstoken, NULL, username, password, NULL, -1, METHOD_GETUSER, azTokenID);
    }
    else
    {
      re = openam_post_authenticate_username_password(handle, conf->openam_authenticate_uri, NULL, username, password, NULL, -1, METHOD_GETUSER, azTokenID);
    }
  }
  
  return re;
};

//////////////////////////////////////////////////////////////////////////////
//
// not in use
//
//
int
be_openam_superuser(void *handle, const char *username)
{
  return 0;
#if 0  
  struct openam_backend *conf = (struct openam_backend *)handle;
  int re, try;

  printf("be_openam_superuser\n");
  re = BACKEND_ERROR;
  try = 0;
  while (re == BACKEND_ERROR && try <= conf->retry_count) {
    try++;
    re = openam_post(handle, conf->openam_authenticate_uri, NULL, username, NULL, NULL, -1, METHOD_SUPERUSER);
//    re = openam_post(handle, conf->superuser_uri, NULL, username, NULL, NULL, -1, METHOD_SUPERUSER);
  }
  return re;
#endif
};

//////////////////////////////////////////////////////////////////////////////
//
//
// 3600 s timeout for the SSO token
    // 
    // 1. Do the authenticate again using the preconfired username/password from the /etc/mosquitto.cong
    // expect an SSO token - which is the TokenID
    //
    // {
      //   "resources" : [
      //     "mqtt+topic://@topicname@
      //    ],
      //   "application": "@auth_opt_openam_application@",
      //   "subject": {
      //     "ssoToken": "@TokenID@"
      //   }
      // }

      // repsonse:
      //
      //  

int
be_openam_aclcheck(void *handle, const char *username, const char *password, const char *topic, int acc)
{
      //printf("*** %s\n", __FUNCTION__);
  fflush(stdout);

  struct openam_backend *conf = (struct openam_backend *)handle;
  int re, try;
  char
    azTokenID[5000];
  azTokenID[0] = 0;
  char
    ssoToken[5000];
  ssoToken[0] = 0;
  re = BACKEND_ERROR;
  try = 0;

  int
    iType = 0;

  openam_post_authenticate_username_password(conf, conf->openam_authenticate_agent_uri, NULL, conf->auth_opt_openam_agent_user, conf->auth_opt_openam_agent_password, topic, acc, METHOD_ACLCHECK, ssoToken);
  
      // do id-token stuff
  while (re == BACKEND_ERROR && try <= conf->retry_count)
  {
    try++;
    
    if (strcmp(username, "_authn_openid_") == 0)
    {
      iType = 1;
      re = openam_post_authenticate_idtoken(conf, conf->openam_authenticate_idtoken, NULL, username, password, NULL, -1, METHOD_ACLCHECK, azTokenID);
    }
    else if (strcmp(username, "_authn_access_token_") == 0)
    {
      iType = 2;
          // do access token stuff
      re = openam_post_authenticate_accesstoken(conf, conf->openam_authenticate_accesstoken, NULL, username, password, NULL, -1, METHOD_ACLCHECK, azTokenID);
    }
    else
    {
      iType = 0;
      re = openam_post_authenticate_username_password(conf, conf->openam_authenticate_agent_uri, NULL, conf->auth_opt_openam_agent_user, conf->auth_opt_openam_agent_password, topic, acc, METHOD_ACLCHECK, azTokenID);
    }

  }
  
  if (re == BACKEND_ALLOW)
  {
    re = BACKEND_ERROR;
    try = 0;
    while (re == BACKEND_ERROR && try <= conf->retry_count)
    {
      try++;
      re = openam_post_authorize(conf, conf->openam_authorize_user_uri, NULL, username, password, topic, acc, iType, azTokenID, ssoToken);
    }
  }
  
  return re;
};
#endif /* BE_HTTP */

