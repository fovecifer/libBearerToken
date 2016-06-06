#include <stdio.h>
#include <stdlib.h>
#include "bearer_token.h"
/*
 * 
 */
int main(int argc, char** argv) {
    int ret;
    bearer_token_t *b_token;
    ret = bearer_token_new(&b_token);
    
    ret = bearer_token_set_alg(b_token, JWT_ALG_RS256);
    
    jwt_alg_t j_alg = brarer_token_get_alg(b_token);
    
    ret = bearer_token_set_pk_file_name(b_token, "./server.key");
    
    ret = bearer_token_load_pk(b_token);
    
    ret = bearer_token_init(b_token);
    
    ret = bearer_token_set_expiration(b_token, 1000);
    
    ret = bearer_token_set_iss(b_token, "Acme auth server");
    
    ret = bearer_token_set_sub(b_token, "admin");
    
    ret = bearer_token_set_aud(b_token, "registry.docker.io");
    
    ret = bearer_token_add_access(b_token, "repository", "samalba/my-app", 
            ACCESS_ACTION_PULL | ACCESS_ACTION_PUSH);
    
    char *result;
    ret = bearer_token_dump_string(b_token, &result);
    
    printf("result: %s\n", result);
    
    bearer_token_free(b_token);

    return (EXIT_SUCCESS);
}

