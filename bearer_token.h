#ifndef BEARER_TOKEN_H
#define BEARER_TOKEN_H

#include <stdint.h>

#include "json.h"
#include "json_object.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#define ACCESS_ACTION_NONE    0
    
#define ACCESS_ACTION_PULL    (1<<0)

#define ACCESS_ACTION_PUSH    (1<<1)

typedef struct _bearer_token bearer_token_t;

typedef enum jwt_alg {
    JWT_ALG_NONE = 0,
    JWT_ALG_RS256,
    JWT_ALG_HS256
} jwt_alg_t;

int bearer_token_new(bearer_token_t **bearer_token);

int bearer_token_set_alg(bearer_token_t *token, jwt_alg_t alg);

jwt_alg_t brarer_token_get_alg(bearer_token_t *token);

int bearer_token_set_pk_file_name(bearer_token_t *token, const char *pk_name);

int bearer_token_load_pk(bearer_token_t *token);

int bearer_token_init(bearer_token_t *token);

int bearer_token_set_expiration(bearer_token_t *token, int64_t expiration);

int bearer_token_set_iss(bearer_token_t *token, char *iss);

int bearer_token_set_sub(bearer_token_t *token, char *sub);

int bearer_token_set_aud(bearer_token_t *token, char *aud);

int bearer_token_add_access(bearer_token_t *token, char *type, char *name, int actions);

int bearer_token_del_all_access(bearer_token_t *token);

int bearer_token_dump_string(bearer_token_t *token, char **out);

void bearer_token_free(bearer_token_t *token);

#ifdef __cplusplus
}
#endif

#endif /* BEARER_TOKEN_H */

