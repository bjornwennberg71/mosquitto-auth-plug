/*
 * bjornwennberg71@gmail.com
 *
 * built upon be-openam.h
 *
 */
#ifdef BE_OPENAM

#define MAXPARAMSLEN  1024
#define METHOD_GETUSER   1
//#define METHOD_SUPERUSER 2
#define METHOD_ACLCHECK  3

struct openam_backend {
	char *hostname;
	int port;
	char *hostheader;
	char *getuser_uri;
//	char *superuser_uri;
	char *aclcheck_uri;
	char *getuser_envs;
//	char *superuser_envs;
	char *aclcheck_envs;
	char *with_tls;
  int   is_tls;
	char *basic_auth;
	int retry_count;
        char *auth_opt_openam_host; // myiot-am.forgerocklabs.net
        int   auth_opt_openam_port; // 8080
        char *auth_opt_openam_path; // /openam
        char *auth_opt_openam_realm; // /edgecontroller
        char *auth_opt_openam_cookiename; // iPlanetDirectoryPro
        char *auth_opt_openam_agent_realm; //     auth realm
        char *auth_opt_openam_agent_user; //      amadmin
        char *auth_opt_openam_agent_password; //  Forger0ck!
        char *auth_opt_openam_client_id; //      egdecontroller
        char *auth_opt_openam_client_secret; //  password2
        char *auth_opt_openam_application; //  things

        char *openam_authenticate_uri; // constructed
        char *openam_authenticate_agent_uri; // constructed [authenticate the agent]
        char *openam_authorize_user_uri; // constructed [authorize the client]
        char *openam_authenticate_idtoken; // constructed [authorize using idtoken]
        char *openam_authenticate_accesstoken; // constructed [authorize using idtoken]
  
};

void *be_openam_init();
void  be_openam_destroy(void *conf);
int   be_openam_getuser(void *conf, const char *username, const char *password, char **phash);
int   be_openam_superuser(void *conf, const char *username);
int   be_openam_aclcheck(void *conf, const char *clientid, const char *username, const char *topic, int acc);

#endif /* BE_OPENAM */
