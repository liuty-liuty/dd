#include <string.h>
#include "hash.h"
#include "sha256.h"
#include "config.h"
#if SUPPORT_SHA3
#include <KeccakHash.h>
#endif
#include "hss_zeroize.h"

#define ALLOW_VERBOSE 0  /* 1 -> we allow the dumping of intermediate */
                         /*      states.  Useful for debugging; horrid */
                         /*      for security */

/*
 * This is the file that implements the hashing APIs we use internally.
 * At the present, our parameter sets support only one hash function
 * (SHA-256, using full 256 bit output), however, that is likely to change
 * in the future
 */

#if ALLOW_VERBOSE
#include <stdio.h>
#include <stdbool.h>
/*
 * Debugging flag; if this is set, we chat about what we're hashing, and what
 * the result is it's useful when debugging; however we probably don't want to
 * do this if we're multithreaded...
 */
bool hss_verbose = false;
#endif

/*
 * This will hash the message, given the hash type. It assumes that the result
 * buffer is large enough for the hash
 */
void hss_hash_ctx(void *result, int hash_type, union hash_context *ctx,
          const void *message, size_t message_len) {
    unsigned hash_len = 32;
#if ALLOW_VERBOSE
    if (hss_verbose) {
        int i; for (i=0; i< message_len; i++) printf( " %02x%s", ((unsigned char*)message)[i], (i%16 == 15) ? "\n" : "" );
    }
#endif

    switch (hash_type) {
    case HASH_SHA256: {
        SHA256_Init(&ctx->sha256);
        SHA256_Update(&ctx->sha256, message, message_len);
        SHA256_Final(result, &ctx->sha256);
        break;
    }
    case HASH_SHA256_24: {
        unsigned char temp[SHA256_LEN];
        SHA256_Init(&ctx->sha256);
        SHA256_Update(&ctx->sha256, message, message_len);
        SHA256_Final(temp, &ctx->sha256);
        memcpy(result, temp, 24 );
        hss_zeroize(temp, sizeof temp);
        hash_len = 24;
        break;
    }
#if SUPPORT_SHA3
    case HASH_SHAKE_24: hash_len = 24;
        /* FALL THRU */
    case HASH_SHAKE:
        Keccak_HashInitialize_SHAKE256(&ctx->shake);
        Keccak_HashUpdate(&ctx->shake, message, 8 * message_len );
        Keccak_HashFinal(&ctx->shake, 0 );
        Keccak_HashSqueeze(&ctx->shake, result, 8 * hash_len );
        break;
#endif
    default:
        return;
    }
#if ALLOW_VERBOSE
    if (hss_verbose) {
        printf( " ->" );
        int i; for (i=0; i<hash_len; i++) printf( " %02x", ((unsigned char *)result)[i] ); printf( "\n" );
    }
#endif
}

void hss_hash(void *result, int hash_type,
          const void *message, size_t message_len) {
    union hash_context ctx;
    hss_hash_ctx(result, hash_type, &ctx, message, message_len);
    hss_zeroize(&ctx, sizeof ctx);
}


/*
 * This provides an API to do incremental hashing.  We use it when hashing the
 * message; since we don't know how long it could be, we don't want to
 * allocate a buffer that's long enough for that, plus the decoration we add
 */
void hss_init_hash_context(int h, union hash_context *ctx) {
    switch (h) {
    case HASH_SHA256: case HASH_SHA256_24:
        SHA256_Init( &ctx->sha256 );
        break;
#if SUPPORT_SHA3
    case HASH_SHAKE: case HASH_SHAKE_24:
        Keccak_HashInitialize_SHAKE256(&ctx->shake);
        break;
#endif
    }
}

void hss_update_hash_context(int h, union hash_context *ctx,
                         const void *msg, size_t len_msg) {
#if ALLOW_VERBOSE
    if (hss_verbose) {
        int i; for (i=0; i<len_msg; i++) printf( " %02x", ((unsigned char*)msg)[i] );
    }
#endif
    switch (h) {
    case HASH_SHA256: case HASH_SHA256_24:
        SHA256_Update(&ctx->sha256, msg, len_msg);
        break;
#if SUPPORT_SHA3
    case HASH_SHAKE: case HASH_SHAKE_24:
        Keccak_HashUpdate(&ctx->shake, msg, 8 * len_msg );
        break;
#endif
    }
}

void hss_finalize_hash_context(int h, union hash_context *ctx, void *buffer) {
    unsigned hash_len = 32;
    switch (h) {
    case HASH_SHA256:
        SHA256_Final(buffer, &ctx->sha256);
        break;
    case HASH_SHA256_24: {
        unsigned char temp[SHA256_LEN];
        SHA256_Final(temp, &ctx->sha256);
        memcpy(buffer, temp, 24);
        hss_zeroize(temp, sizeof temp);
        hash_len = 24;
        break;
    }
#if SUPPORT_SHA3
    case HASH_SHAKE_24: hash_len = 24;
        /* FALL THRU */
    case HASH_SHAKE:
        Keccak_HashFinal(&ctx->shake, 0 );
        Keccak_HashSqueeze(&ctx->shake, buffer, 8 * hash_len );
        break;
#endif
    default:
        return;
    }

#if ALLOW_VERBOSE
    if (hss_verbose) {
        printf( " -->" );
        int i; for (i=0; i<hash_len; i++) printf( " %02x", ((unsigned char*)buffer)[i] );
        printf( "\n" );
    }
#endif
}


unsigned hss_hash_length(int hash_type) {
    switch (hash_type) {
    case HASH_SHA256: return 32;
    case HASH_SHA256_24: return 24;
#if SUPPORT_SHA3
    case HASH_SHAKE: return 32;
    case HASH_SHAKE_24: return 24;
#endif
    }
    return 0;
}

unsigned hss_hash_blocksize(int hash_type) {
    switch (hash_type) {
    case HASH_SHA256: case HASH_SHA256_24:return 64;
#if SUPPORT_SHA3
    case HASH_SHAKE:
    case HASH_SHAKE_24: return 136;
        /* This is used only for doing HMAC for the aux data */
        /* Would it make more sence to either use a SHA256 hash, or KMAC? */
#endif
    }
    return 0;
}

