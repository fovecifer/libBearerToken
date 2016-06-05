#include "bearer_token.h"
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>

static int KID_LENGTH = 60;
static char *TYP = "typ";
static char *ALG = "alg";
static char *JWT = "JWT";
static char *KID = "kid";

typedef struct _base64_url_hash {
    char *hash;
    int32_t size;
}base64_url_hash_t;

typedef union pk {
    RSA *rsa;
    DSA *dsa;
    DH  *dh;
    EC_KEY *ec;
}PK;

struct _bearer_token {
    FILE *prk_file;
    jwt_alg_t alg;
    EVP_PKEY *prk;
    PK pk;
    char *kid;
    json_object *JOSE_header;
    base64_url_hash_t *JOSE_header_hash;
    json_object *Claim_set;
    int64_t expiration;
    base64_url_hash_t *Claim_set_hash;
    json_object *accesses;
    json_object *token;
};

/* C89 compliant way to cast 'char' to 'unsigned char'. */
static unsigned char
to_uchar(char ch) {
    return ch;
}

static void BIN2HEX(unsigned char *hash, unsigned char hex[2 * SHA256_DIGEST_LENGTH + 1]) {
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hash[2 * SHA256_DIGEST_LENGTH] = 0;
}

//static const char b64c[64] =
//  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char b64c[64] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* Base64 encode IN array of size INLEN into OUT array. OUT needs
   to be of length >= BASE64_LENGTH(INLEN), and INLEN needs to be
   a multiple of 3.  */

static void base64_encode_fast(const char *restrict in, size_t inlen, char *restrict out) {
    while (inlen) {
        *out++ = b64c[to_uchar(in[0]) >> 2];
        *out++ = b64c[((to_uchar(in[0]) << 4) + (to_uchar(in[1]) >> 4)) & 0x3f];
        *out++ = b64c[((to_uchar(in[1]) << 2) + (to_uchar(in[2]) >> 6)) & 0x3f];
        *out++ = b64c[to_uchar(in[2]) & 0x3f];

        inlen -= 3;
        in += 3;
    }
}

/* Base64 encode IN array of size INLEN into OUT array of size OUTLEN.
   If OUTLEN is less than BASE64_LENGTH(INLEN), write as many bytes as
   possible.  If OUTLEN is larger than BASE64_LENGTH(INLEN), also zero
   terminate the output buffer. */
static void base64_encode(const char *restrict in, size_t inlen,
        char *restrict out, size_t outlen) {
    /* Note this outlen constraint can be enforced at compile time.
       I.E. that the output buffer is exactly large enough to hold
       the encoded inlen bytes.  The inlen constraints (of corresponding
       to outlen, and being a multiple of 3) can change at runtime
       at the end of input.  However the common case when reading
       large inputs is to have both constraints satisfied, so we depend
       on both in base_encode_fast().  */
    if (outlen % 4 == 0 && inlen == outlen / 4 * 3) {
        base64_encode_fast(in, inlen, out);
        return;
    }

    while (inlen && outlen) {
        *out++ = b64c[to_uchar(in[0]) >> 2];
        if (!--outlen)
            break;
        *out++ = b64c[((to_uchar(in[0]) << 4)
                + (--inlen ? to_uchar(in[1]) >> 4 : 0))
                & 0x3f];
        if (!--outlen)
            break;
        *out++ =
                (inlen
                ? b64c[((to_uchar(in[1]) << 2)
                + (--inlen ? to_uchar(in[2]) >> 6 : 0))
                & 0x3f]
                : '=');
        if (!--outlen)
            break;
        *out++ = inlen ? b64c[to_uchar(in[2]) & 0x3f] : '=';
        if (!--outlen)
            break;
        if (inlen)
            inlen--;
        if (inlen)
            in += 3;
    }

    if (outlen)
        *out = '\0';
}

static size_t url_base64_length(char *hash) {
    int i;
    size_t length = strlen(hash);
    for(i = 0; i < length; i++) {
        if(hash[i] == '=') {
            break;
        }
    }
    return i;
}

/**
 * Let this be a sequence of plain data before encoding:
 *
 *  01234567 01234567 01234567 01234567 01234567
 * +--------+--------+--------+--------+--------+
 * |< 0 >< 1| >< 2 ><|.3 >< 4.|>< 5 ><.|6 >< 7 >|
 * +--------+--------+--------+--------+--------+
 *
 * There are 5 octets of 8 bits each in each sequence.
 * There are 8 blocks of 5 bits each in each sequence.
 *
 * You probably want to refer to that graph when reading the algorithms in this
 * file. We use "octet" instead of "byte" intentionnaly as we really work with
 * 8 bits quantities. This implementation will probably not work properly on
 * systems that don't have exactly 8 bits per (unsigned) char.
 **/

static size_t min(size_t x, size_t y) {
    return x < y ? x : y;
}

static const unsigned char PADDING_CHAR = '=';

/**
 * Pad the given buffer with len padding characters.
 */
static void pad(unsigned char *buf, int len) {
    int i;
    for (i = 0; i < len; i++)
        buf[i] = PADDING_CHAR;
}

/**
 * This convert a 5 bits value into a base32 character.
 * Only the 5 least significant bits are used.
 */
static unsigned char encode_char(unsigned char c) {
    static unsigned char base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    return base32[c & 0x1F]; // 0001 1111
}

/**
 * Decode given character into a 5 bits value. 
 * Returns -1 iff the argument given was an invalid base32 character
 * or a padding character.
 */
static int decode_char(unsigned char c) {
    char retval = -1;

    if (c >= 'A' && c <= 'Z')
        retval = c - 'A';
    if (c >= '2' && c <= '7')
        retval = c - '2' + 26;

    assert(retval == -1 || ((retval & 0x1F) == retval));

    return retval;
}

/**
 * Given a block id between 0 and 7 inclusive, this will return the index of
 * the octet in which this block starts. For example, given 3 it will return 1
 * because block 3 starts in octet 1:
 *
 * +--------+--------+
 * | ......<|.3 >....|
 * +--------+--------+
 *  octet 1 | octet 2
 */
static int get_octet(int block) {
    assert(block >= 0 && block < 8);
    return (block * 5) / 8;
}

/**
 * Given a block id between 0 and 7 inclusive, this will return how many bits
 * we can drop at the end of the octet in which this block starts. 
 * For example, given block 0 it will return 3 because there are 3 bits
 * we don't care about at the end:
 *
 *  +--------+-
 *  |< 0 >...|
 *  +--------+-
 *
 * Given block 1, it will return -2 because there
 * are actually two bits missing to have a complete block:
 *
 *  +--------+-
 *  |.....< 1|..
 *  +--------+-
 **/
static int get_offset(int block) {
    assert(block >= 0 && block < 8);
    return (8 - 5 - (5 * block) % 8);
}

/**
 * Like "b >> offset" but it will do the right thing with negative offset.
 * We need this as bitwise shifting by a negative offset is undefined
 * behavior.
 */
static unsigned char shift_right(unsigned char byte, char offset) {
    if (offset > 0)
        return byte >> offset;
    else
        return byte << -offset;
}

static unsigned char shift_left(unsigned char byte, char offset) {
    return shift_right(byte, -offset);
}

/**
 * Encode a sequence. A sequence is no longer than 5 octets by definition.
 * Thus passing a length greater than 5 to this function is an error. Encoding
 * sequences shorter than 5 octets is supported and padding will be added to the
 * output as per the specification.
 */
static void encode_sequence(const unsigned char *plain, int len, unsigned char *coded) {
    assert(CHAR_BIT == 8); // not sure this would work otherwise
    assert(len >= 0 && len <= 5);

    int block;
    for (block = 0; block < 8; block++) {
        int octet = get_octet(block); // figure out which octet this block starts in
        int junk = get_offset(block); // how many bits do we drop from this octet?

        if (octet >= len) { // we hit the end of the buffer
            pad(&coded[block], 8 - block);
            return;
        }

        unsigned char c = shift_right(plain[octet], junk); // first part

        if (junk < 0 // is there a second part?
                && octet < len - 1) // is there still something to read?
        {
            c |= shift_right(plain[octet + 1], 8 + junk);
        }
        coded[block] = encode_char(c);
    }
}

static void base32_encode(const unsigned char *plain, size_t len, unsigned char *coded) {
    // All the hard work is done in encode_sequence(),
    // here we just need to feed it the data sequence by sequence.
    int i, j;
    for (i = 0, j = 0; i < len; i += 5, j += 8) {
        encode_sequence(&plain[i], min(len - i, 5), &coded[j]);
    }
}

static void base32_kid_encode(const unsigned char *plain, unsigned char *coded) {
    unsigned char tmp[48];
    base32_encode(plain, 30, tmp);
    int i = 0, j = 0;
    for (; i < 48; i++, j++) {
        if (i > 0 && (i % 4) == 0) {
            coded[j] = ':';
            j++;
        }
        coded[j] = tmp[i];
    }
    coded[KID_LENGTH] = 0;
}


int bearer_token_new(bearer_token_t **token) {
    bearer_token_t *tmp_token;
    
    if(!token) {
        return EINVAL;
    }
    
    tmp_token = (bearer_token_t *) calloc(sizeof(bearer_token_t), 1);
    if(!tmp_token) {
        return ENOMEM;
    }
    
    tmp_token->JOSE_header = json_object_new_object();
    tmp_token->Claim_set = json_object_new_object();
    tmp_token->accesses = json_object_new_array();
    tmp_token->token = json_object_new_object();
    
    *token = tmp_token;
    return 0;
}

int bearer_token_set_alg(bearer_token_t *token, jwt_alg_t alg) {
    token->alg = alg;
    return 0;
}

jwt_alg_t brarer_token_get_alg(bearer_token_t *token) {
    return token->alg;
}

int bearer_token_set_pk_file_name(bearer_token_t *token, const char *pk_name) {
    struct stat tmp;
    int ret = stat(pk_name, &tmp);
    if(ret == 0) {
        token->prk_file = fopen(pk_name, "r");
    }
    return ret;
}

int bearer_token_load_pk(bearer_token_t *token) {
    if(token->prk_file == NULL) {
        return ENOENT;
    }
    
    EVP_PKEY *tmp_prk;
    
    
    
    /* read private key */
    tmp_prk = PEM_read_PrivateKey(token->prk_file, &tmp_prk,
            NULL, NULL);
    if(tmp_prk == NULL) {
        return EPERM;
    }
    token->prk = tmp_prk;
    
    
    /* for RS*** alg */
    if(token->alg == JWT_ALG_RS256) {
        RSA *tmp_rsa = EVP_PKEY_get1_RSA(tmp_prk);
        if(tmp_rsa == NULL) {
            return EPERM;
        }
        token->pk.rsa = tmp_rsa;
        return rsa_generate_kid(token, tmp_rsa);
    }
    
    return 0;
    
}

static int rsa_generate_kid(bearer_token_t *token, RSA *tmp_rsa) {
    BIO *out = NULL;
    int ret;
    out = BIO_new(BIO_s_mem());

    ret = i2d_RSA_PUBKEY_bio(out, tmp_rsa);
    if (ret < 0) {
        return ret;
    }
    /* generate kid */
    char *buff;
    long mem_size = BIO_get_mem_data(out, &buff);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(buff, mem_size, hash);

    unsigned char *base32_kid_hash = (unsigned char *) calloc(sizeof (char) * (KID_LENGTH + 1), 1);
    if (base32_kid_hash == NULL) {
        return ENOMEM;
    }
    base32_kid_encode(hash, base32_kid_hash);
    token->kid = base32_kid_hash;
    
    if (out != NULL) {
        BIO_free_all(out);
    }
    
    return 0;
}

static const char *alg_to_str(jwt_alg_t alg)
{
	switch (alg) {
	case JWT_ALG_NONE:
		return "none";
	case JWT_ALG_RS256:
		return "RS256";
	case JWT_ALG_HS256:
		return "HS256";
	}

	return NULL; // LCOV_EXCL_LINE
}

static void update_JOSE_header(bearer_token_t *token) {
    json_object_object_add(token->JOSE_header, TYP, json_object_new_string(JWT));
    json_object_object_add(token->JOSE_header, ALG, json_object_new_string(alg_to_str(token->alg)));
    json_object_object_add(token->JOSE_header, KID, json_object_new_string(token->kid));
}

int bearer_token_init(bearer_token_t *token) {
    update_JOSE_header(token);
}

int bearer_token_set_expiration(bearer_token_t *token, int64_t expiration) {
    if(expiration < 0) {
        return EINVAL;
    }
    
    token->expiration = experation;
    return 0;
}


