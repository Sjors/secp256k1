/***********************************************************************
 * Distributed under the MIT software license, see the accompanying      *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.   *
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORRSIG_TESTS_ANTI_EXFIL_IMPL_H
#define SECP256K1_MODULE_SCHNORRSIG_TESTS_ANTI_EXFIL_IMPL_H

#include "../../../include/secp256k1_anti_exfil.h"
#include "anti_exfil_vectors.h"

static void anti_exfil_unhex(unsigned char *out, const char *hex, size_t size) {
    size_t i;
    CHECK(strlen(hex) == 2 * size);
    for (i = 0; i < size; ++i) {
        unsigned int value;
        CHECK(sscanf(hex + 2 * i, "%2x", &value) == 1);
        out[i] = value;
    }
}

static void test_schnorrsig_anti_exfil_vectors(void) {
    size_t i;
    for (i = 0; i < sizeof(secp256k1_anti_exfil_vectors) / sizeof(secp256k1_anti_exfil_vectors[0]); ++i) {
        unsigned char sk[32], pk32[32], msg[32], rho[32], commitment[32], expected_commitment[32];
        unsigned char nonce33[33], expected_nonce33[33], sig[64], expected_sig[64], normal_sig[64];
        size_t nonce_len = sizeof(nonce33);
        secp256k1_keypair keypair;
        secp256k1_xonly_pubkey pk;
        secp256k1_pubkey nonce;
        anti_exfil_unhex(sk, secp256k1_anti_exfil_vectors[i].secret_key, sizeof(sk));
        anti_exfil_unhex(pk32, secp256k1_anti_exfil_vectors[i].public_key, sizeof(pk32));
        anti_exfil_unhex(msg, secp256k1_anti_exfil_vectors[i].message, sizeof(msg));
        anti_exfil_unhex(rho, secp256k1_anti_exfil_vectors[i].host_nonce, sizeof(rho));
        anti_exfil_unhex(expected_commitment, secp256k1_anti_exfil_vectors[i].host_commitment, sizeof(expected_commitment));
        anti_exfil_unhex(expected_nonce33, secp256k1_anti_exfil_vectors[i].signer_nonce, sizeof(expected_nonce33));
        anti_exfil_unhex(expected_sig, secp256k1_anti_exfil_vectors[i].signature, sizeof(expected_sig));
        CHECK(secp256k1_keypair_create(CTX, &keypair, sk));
        CHECK(secp256k1_xonly_pubkey_parse(CTX, &pk, pk32));
        CHECK(secp256k1_schnorrsig_anti_exfil_host_commit(STATIC_CTX, commitment, rho));
        CHECK(secp256k1_memcmp_var(commitment, expected_commitment, 32) == 0);
        CHECK(secp256k1_schnorrsig_anti_exfil_signer_commit(CTX, &nonce, msg, &keypair, commitment));
        CHECK(secp256k1_ec_pubkey_serialize(STATIC_CTX, nonce33, &nonce_len, &nonce, SECP256K1_EC_COMPRESSED));
        CHECK(secp256k1_memcmp_var(nonce33, expected_nonce33, 33) == 0);
        CHECK(secp256k1_schnorrsig_anti_exfil_sign(CTX, sig, msg, &keypair, rho));
        CHECK(secp256k1_memcmp_var(sig, expected_sig, 64) == 0);
        CHECK(secp256k1_schnorrsig_anti_exfil_host_verify(STATIC_CTX, sig, msg, &pk, rho, &nonce));
        CHECK(secp256k1_schnorrsig_verify(STATIC_CTX, sig, msg, 32, &pk));
        /* The anti-exfil nonce must not be the ordinary BIP340 nonce with the
         * same aux input. Such cross-protocol reuse would expose the key. */
        CHECK(secp256k1_schnorrsig_sign32(CTX, normal_sig, msg, &keypair, commitment));
        CHECK(secp256k1_memcmp_var(normal_sig, nonce33 + 1, 32) != 0);
        CHECK(!secp256k1_schnorrsig_anti_exfil_host_verify(STATIC_CTX, normal_sig, msg, &pk, rho, &nonce));
    }
}

static void test_schnorrsig_anti_exfil_api(void) {
    unsigned char sk[32] = { 0 }, rho[32] = { 0 }, msg[32] = { 0 }, commitment[32], sig[64];
    secp256k1_keypair keypair, invalid_keypair = {{ 0 }};
    secp256k1_pubkey nonce;
    secp256k1_xonly_pubkey pk;
    sk[31] = 3;
    rho[31] = 1;
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk));
    CHECK(secp256k1_keypair_xonly_pub(CTX, &pk, NULL, &keypair));
    CHECK(secp256k1_schnorrsig_anti_exfil_host_commit(CTX, commitment, rho));
    CHECK(secp256k1_schnorrsig_anti_exfil_signer_commit(CTX, &nonce, msg, &keypair, commitment));
    CHECK(secp256k1_schnorrsig_anti_exfil_sign(CTX, sig, msg, &keypair, rho));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_host_commit(CTX, NULL, rho));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_host_commit(CTX, commitment, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_signer_commit(CTX, NULL, msg, &keypair, commitment));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_signer_commit(CTX, &nonce, NULL, &keypair, commitment));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_signer_commit(CTX, &nonce, msg, NULL, commitment));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_signer_commit(CTX, &nonce, msg, &keypair, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_signer_commit(CTX, &nonce, msg, &invalid_keypair, commitment));
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_schnorrsig_anti_exfil_signer_commit(STATIC_CTX, &nonce, msg, &keypair, commitment));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_sign(CTX, NULL, msg, &keypair, rho));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_sign(CTX, sig, NULL, &keypair, rho));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_sign(CTX, sig, msg, NULL, rho));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_sign(CTX, sig, msg, &keypair, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_sign(CTX, sig, msg, &invalid_keypair, rho));
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_schnorrsig_anti_exfil_sign(STATIC_CTX, sig, msg, &keypair, rho));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_host_verify(CTX, NULL, msg, &pk, rho, &nonce));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, NULL, &pk, rho, &nonce));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, msg, NULL, rho, &nonce));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, msg, &pk, NULL, &nonce));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, msg, &pk, rho, NULL));
}

static void test_schnorrsig_anti_exfil_failures(void) {
    unsigned char sk[32] = { 0 }, rho[32] = { 0 }, msg[32] = { 0 }, commitment[32], sig[64], retry_sig[64], zero64[64] = { 0 };
    unsigned char changed[32], order[32], serialized[33], retry_serialized[33];
    size_t serialized_len;
    secp256k1_keypair keypair;
    secp256k1_pubkey nonce, retry_nonce, changed_nonce;
    secp256k1_xonly_pubkey pk, changed_pk;
    sk[31] = 6;
    rho[31] = 2;
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk));
    CHECK(secp256k1_keypair_xonly_pub(CTX, &pk, NULL, &keypair));
    CHECK(secp256k1_schnorrsig_anti_exfil_host_commit(CTX, commitment, rho));
    CHECK(secp256k1_schnorrsig_anti_exfil_signer_commit(CTX, &nonce, msg, &keypair, commitment));
    CHECK(secp256k1_schnorrsig_anti_exfil_sign(CTX, sig, msg, &keypair, rho));
    CHECK(secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, msg, &pk, rho, &nonce));
    /* A retry is deterministic and preserves the original public nonce. */
    CHECK(secp256k1_schnorrsig_anti_exfil_signer_commit(CTX, &retry_nonce, msg, &keypair, commitment));
    serialized_len = 33;
    CHECK(secp256k1_ec_pubkey_serialize(CTX, serialized, &serialized_len, &nonce, SECP256K1_EC_COMPRESSED));
    serialized_len = 33;
    CHECK(secp256k1_ec_pubkey_serialize(CTX, retry_serialized, &serialized_len, &retry_nonce, SECP256K1_EC_COMPRESSED));
    CHECK(secp256k1_memcmp_var(serialized, retry_serialized, 33) == 0);
    CHECK(secp256k1_schnorrsig_anti_exfil_sign(CTX, retry_sig, msg, &keypair, rho));
    CHECK(secp256k1_memcmp_var(sig, retry_sig, 64) == 0);
    /* Mismatched message, key, scalar opening, commitment, or nonce parity. */
    memcpy(changed, msg, 32);
    changed[0] ^= 1;
    CHECK(!secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, changed, &pk, rho, &nonce));
    CHECK(secp256k1_xonly_pubkey_tweak_add(CTX, &changed_nonce, &pk, rho));
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &changed_pk, NULL, &changed_nonce));
    CHECK(!secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, msg, &changed_pk, rho, &nonce));
    memcpy(changed, rho, 32);
    changed[31] ^= 1;
    CHECK(!secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, msg, &pk, changed, &nonce));
    CHECK(secp256k1_schnorrsig_anti_exfil_sign(CTX, retry_sig, msg, &keypair, changed));
    CHECK(secp256k1_schnorrsig_verify(CTX, retry_sig, msg, 32, &pk));
    CHECK(!secp256k1_schnorrsig_anti_exfil_host_verify(CTX, retry_sig, msg, &pk, changed, &nonce));
    memcpy(changed, commitment, 32);
    changed[0] ^= 1;
    CHECK(secp256k1_schnorrsig_anti_exfil_signer_commit(CTX, &changed_nonce, msg, &keypair, changed));
    CHECK(!secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, msg, &pk, rho, &changed_nonce));
    changed_nonce = nonce;
    CHECK(secp256k1_ec_pubkey_negate(CTX, &changed_nonce));
    CHECK(!secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, msg, &pk, rho, &changed_nonce));
    memcpy(retry_sig, sig, 64);
    retry_sig[63] ^= 1;
    CHECK(!secp256k1_schnorrsig_anti_exfil_host_verify(CTX, retry_sig, msg, &pk, rho, &nonce));
    /* Malformed nonce encodings must be rejected before entering host_verify. */
    serialized[0] = 4;
    CHECK(!secp256k1_ec_pubkey_parse(CTX, &changed_nonce, serialized, 33));
    memset(serialized, 0, 33);
    CHECK(!secp256k1_ec_pubkey_parse(CTX, &changed_nonce, serialized, 33));
    /* R0 + rho*G at infinity is a protocol failure. */
    CHECK(secp256k1_ec_pubkey_create(CTX, &changed_nonce, rho));
    CHECK(secp256k1_ec_pubkey_negate(CTX, &changed_nonce));
    CHECK(!secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, msg, &pk, rho, &changed_nonce));
    /* Zero and overflow scalar openings are invalid and outputs are cleared. */
    memset(changed, 0, 32);
    CHECK(!secp256k1_schnorrsig_anti_exfil_host_commit(CTX, commitment, changed));
    CHECK(secp256k1_memcmp_var(commitment, zero64, 32) == 0);
    CHECK(!secp256k1_schnorrsig_anti_exfil_sign(CTX, retry_sig, msg, &keypair, changed));
    CHECK(secp256k1_memcmp_var(retry_sig, zero64, 64) == 0);
    CHECK(!secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, msg, &pk, changed, &nonce));
    anti_exfil_unhex(order, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 32);
    CHECK(!secp256k1_schnorrsig_anti_exfil_host_commit(CTX, commitment, order));
    CHECK(!secp256k1_schnorrsig_anti_exfil_sign(CTX, retry_sig, msg, &keypair, order));
    CHECK(secp256k1_memcmp_var(retry_sig, zero64, 64) == 0);
    CHECK(!secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, msg, &pk, order, &nonce));
    memset(changed, 0xff, 32);
    CHECK(!secp256k1_schnorrsig_anti_exfil_host_commit(CTX, commitment, changed));
    CHECK(!secp256k1_schnorrsig_anti_exfil_sign(CTX, retry_sig, msg, &keypair, changed));
    CHECK(secp256k1_memcmp_var(retry_sig, zero64, 64) == 0);
}

static void test_schnorrsig_anti_exfil_randomized(void) {
    unsigned int i;
    for (i = 0; i < 32; ++i) {
        unsigned char sk[32], rho[32], msg[32], commitment[32], sig[64];
        secp256k1_keypair keypair;
        secp256k1_xonly_pubkey pk;
        secp256k1_pubkey nonce;
        do { testrand256(sk); } while (!secp256k1_ec_seckey_verify(CTX, sk));
        do { testrand256(rho); } while (!secp256k1_ec_seckey_verify(CTX, rho));
        testrand256(msg);
        CHECK(secp256k1_keypair_create(CTX, &keypair, sk));
        CHECK(secp256k1_keypair_xonly_pub(CTX, &pk, NULL, &keypair));
        CHECK(secp256k1_schnorrsig_anti_exfil_host_commit(CTX, commitment, rho));
        CHECK(secp256k1_schnorrsig_anti_exfil_signer_commit(CTX, &nonce, msg, &keypair, commitment));
        CHECK(secp256k1_schnorrsig_anti_exfil_sign(CTX, sig, msg, &keypair, rho));
        CHECK(secp256k1_schnorrsig_anti_exfil_host_verify(CTX, sig, msg, &pk, rho, &nonce));
    }
}

#endif /* SECP256K1_MODULE_SCHNORRSIG_TESTS_ANTI_EXFIL_IMPL_H */
