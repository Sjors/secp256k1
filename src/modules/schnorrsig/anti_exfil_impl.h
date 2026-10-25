/***********************************************************************
 * Distributed under the MIT software license, see the accompanying      *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.   *
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORRSIG_ANTI_EXFIL_IMPL_H
#define SECP256K1_MODULE_SCHNORRSIG_ANTI_EXFIL_IMPL_H

#include "../../../include/secp256k1_anti_exfil.h"

static const unsigned char secp256k1_anti_exfil_host_tag[] = "BIP-EXFIL/host";
static const unsigned char secp256k1_anti_exfil_nonce_tag[] = "BIP-EXFIL/nonce";

/* This hash intentionally accepts any 32-byte commitment. The signer only sees
 * the commitment in round one and rederives it from the opening in round two. */
static void secp256k1_anti_exfil_host_hash(const secp256k1_hash_ctx *hash_ctx, unsigned char *commitment32, const unsigned char *rho32) {
    secp256k1_sha256 sha;
    secp256k1_sha256_initialize_tagged(hash_ctx, &sha, secp256k1_anti_exfil_host_tag, sizeof(secp256k1_anti_exfil_host_tag) - 1);
    secp256k1_sha256_write(hash_ctx, &sha, rho32, 32);
    secp256k1_sha256_finalize(hash_ctx, &sha, commitment32);
    secp256k1_sha256_clear(&sha);
}

int secp256k1_schnorrsig_anti_exfil_host_commit(const secp256k1_context *ctx, unsigned char *commitment32, const unsigned char *rho32) {
    secp256k1_scalar rho;
    int ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commitment32 != NULL);
    ARG_CHECK(rho32 != NULL);
    ret = secp256k1_scalar_set_b32_seckey(&rho, rho32);
    secp256k1_anti_exfil_host_hash(&ctx->hash_ctx, commitment32, rho32);
    secp256k1_memczero(commitment32, 32, !ret);
    secp256k1_scalar_clear(&rho);
    return ret;
}

/* Return a normalized secret key and its public key, and the original nonce.
 * As in BIP340, auxiliary randomness masks the normalized key. A dedicated nonce
 * tag prevents reuse with normal BIP340 signing using the same auxiliary data. */
static int secp256k1_anti_exfil_nonce(const secp256k1_context *ctx, secp256k1_scalar *k0, secp256k1_scalar *sk, secp256k1_ge *pk, const unsigned char *msg32, const secp256k1_keypair *keypair, const unsigned char *host_commitment32) {
    unsigned char seckey[32];
    unsigned char pk32[32];
    unsigned char nonce32[32];
    int ret = secp256k1_keypair_load(ctx, sk, pk, keypair);
    if (secp256k1_fe_is_odd(&pk->y)) {
        secp256k1_scalar_negate(sk, sk);
        secp256k1_ge_neg(pk, pk);
    }
    secp256k1_scalar_get_b32(seckey, sk);
    secp256k1_fe_get_b32(pk32, &pk->x);
    ret &= nonce_function_bip340_impl(&ctx->hash_ctx, nonce32, msg32, 32, seckey, pk32, secp256k1_anti_exfil_nonce_tag, sizeof(secp256k1_anti_exfil_nonce_tag) - 1, (void*)host_commitment32);
    secp256k1_scalar_set_b32(k0, nonce32, NULL);
    ret &= !secp256k1_scalar_is_zero(k0);
    secp256k1_memclear_explicit(seckey, sizeof(seckey));
    secp256k1_memclear_explicit(nonce32, sizeof(nonce32));
    return ret;
}

int secp256k1_schnorrsig_anti_exfil_signer_commit(const secp256k1_context *ctx, secp256k1_pubkey *signer_nonce, const unsigned char *msg32, const secp256k1_keypair *keypair, const unsigned char *host_commitment32) {
    secp256k1_scalar k0, sk;
    secp256k1_ge pk, r0;
    int ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(signer_nonce != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(host_commitment32 != NULL);
    ret = secp256k1_anti_exfil_nonce(ctx, &k0, &sk, &pk, msg32, keypair, host_commitment32);
    secp256k1_scalar_cmov(&k0, &secp256k1_scalar_one, !ret);
    secp256k1_ecmult_gen_ge(&ctx->ecmult_gen_ctx, &r0, &k0);
    secp256k1_declassify(ctx, &r0, sizeof(r0));
    secp256k1_pubkey_save(signer_nonce, &r0);
    secp256k1_memczero(signer_nonce, sizeof(*signer_nonce), !ret);
    secp256k1_scalar_clear(&k0);
    secp256k1_scalar_clear(&sk);
    return ret;
}

int secp256k1_schnorrsig_anti_exfil_sign(const secp256k1_context *ctx, unsigned char *sig64, const unsigned char *msg32, const secp256k1_keypair *keypair, const unsigned char *rho32) {
    secp256k1_scalar k, sk, rho, e;
    secp256k1_ge pk, r;
    secp256k1_xonly_pubkey xonly_pk;
    unsigned char commitment32[32];
    unsigned char pk32[32];
    int ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(rho32 != NULL);
    ret = secp256k1_scalar_set_b32_seckey(&rho, rho32);
    secp256k1_anti_exfil_host_hash(&ctx->hash_ctx, commitment32, rho32);
    ret &= secp256k1_anti_exfil_nonce(ctx, &k, &sk, &pk, msg32, keypair, commitment32);
    secp256k1_scalar_add(&k, &k, &rho);
    ret &= !secp256k1_scalar_is_zero(&k);
    secp256k1_scalar_cmov(&k, &secp256k1_scalar_one, !ret);
    secp256k1_ecmult_gen_ge(&ctx->ecmult_gen_ctx, &r, &k);
    secp256k1_declassify(ctx, &r, sizeof(r));
    secp256k1_fe_normalize_var(&r.y);
    if (secp256k1_fe_is_odd(&r.y)) {
        secp256k1_scalar_negate(&k, &k);
    }
    secp256k1_fe_normalize_var(&r.x);
    secp256k1_fe_get_b32(sig64, &r.x);
    secp256k1_fe_get_b32(pk32, &pk.x);
    secp256k1_schnorrsig_challenge(&ctx->hash_ctx, &e, sig64, msg32, 32, pk32);
    secp256k1_scalar_mul(&e, &e, &sk);
    secp256k1_scalar_add(&e, &e, &k);
    secp256k1_scalar_get_b32(sig64 + 32, &e);
    secp256k1_xonly_pubkey_save(&xonly_pk, &pk);
    /* Fault detection is part of the signing protocol. The signature and
     * normalized public key are public, including to constant-time analysis. */
    secp256k1_declassify(ctx, sig64, 64);
    ret &= secp256k1_schnorrsig_verify(ctx, sig64, msg32, 32, &xonly_pk);
    secp256k1_memczero(sig64, 64, !ret);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&sk);
    secp256k1_scalar_clear(&rho);
    secp256k1_scalar_clear(&e);
    return ret;
}

int secp256k1_schnorrsig_anti_exfil_host_verify(const secp256k1_context *ctx, const unsigned char *sig64, const unsigned char *msg32, const secp256k1_xonly_pubkey *pubkey, const unsigned char *rho32, const secp256k1_pubkey *signer_nonce) {
    secp256k1_pubkey combined;
    unsigned char serialized[33];
    size_t serialized_len = sizeof(serialized);
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(rho32 != NULL);
    ARG_CHECK(signer_nonce != NULL);
    if (!secp256k1_ec_seckey_verify(ctx, rho32)) return 0;
    combined = *signer_nonce;
    if (!secp256k1_ec_pubkey_tweak_add(ctx, &combined, rho32)) return 0;
    if (!secp256k1_ec_pubkey_serialize(ctx, serialized, &serialized_len, &combined, SECP256K1_EC_COMPRESSED)) return 0;
    if (secp256k1_memcmp_var(serialized + 1, sig64, 32) != 0) return 0;
    return secp256k1_schnorrsig_verify(ctx, sig64, msg32, 32, pubkey);
}

#endif /* SECP256K1_MODULE_SCHNORRSIG_ANTI_EXFIL_IMPL_H */
