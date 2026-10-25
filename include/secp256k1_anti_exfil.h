#ifndef SECP256K1_ANTI_EXFIL_H
#define SECP256K1_ANTI_EXFIL_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Interactive anti-exfiltration for single-signer BIP340 signatures.
 *
 *  This API is available when the schnorrsig module is enabled. It does not
 *  implement a general sign-to-contract interface or multiparty signing.
 *
 *  The host samples a fresh uniformly random scalar rho in [1, n-1] and sends
 *  host_commit(rho) to the signer, without revealing rho. The signer returns
 *  signer_commit(msg32, keypair, commitment), a full public nonce R0. Only after
 *  recording R0 does the host reveal rho. The signer returns sign(msg32,
 *  keypair, rho), and the host must call host_verify before using the signature.
 *
 *  The host contribution must remain secret until R0 has been received. After
 *  that point a retry must use exactly the same rho and require exactly the
 *  same R0. Do not automatically restart failed sessions with fresh randomness:
 *  selective aborts would let a malicious signer bias published signatures.
 *  Protocol transcripts must not be published alongside signatures.
 *
 *  The signing keypair is the actual BIP340 signing key. For Taproot key-path
 *  signing, apply the Taproot key tweak before invoking either signer function.
 *  Derivation of R0 includes the host commitment and a dedicated nonce hash tag;
 *  this prevents related-nonce key extraction across sessions or signing APIs.
 */

/** Commit to the host's random scalar.
 *
 *  Returns 1 for a scalar in [1, n-1], or 0 otherwise (zeroing commitment32).
 *  Args:             ctx: a secp256k1 context object.
 *  Out: commitment32: a pointer to 32 bytes receiving
 *                    tagged_hash("BIP-EXFIL/host", rho32).
 *  In:         rho32: a uniformly random scalar, encoded as 32 big-endian bytes.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_anti_exfil_host_commit(
    const secp256k1_context *ctx,
    unsigned char *commitment32,
    const unsigned char *rho32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Produce the signer's original public nonce before receiving rho.
 *
 *  Serialize signer_nonce with secp256k1_ec_pubkey_serialize and
 *  SECP256K1_EC_COMPRESSED. The host must retain all 33 bytes, including parity.
 *  The signer can safely recompute its nonce rather than retaining secret state.
 *
 *  Returns 1 on success, or 0 if nonce generation fails (zeroing signer_nonce).
 *  Args:                ctx: a context object, not secp256k1_context_static.
 *  Out:        signer_nonce: the original public nonce R0.
 *  In:                msg32: the 32-byte message being signed.
 *                   keypair: the actual signing keypair.
 *        host_commitment32: the commitment received from the host.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_anti_exfil_signer_commit(
    const secp256k1_context *ctx,
    secp256k1_pubkey *signer_nonce,
    const unsigned char *msg32,
    const secp256k1_keypair *keypair,
    const unsigned char *host_commitment32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Sign after receiving the host's opening rho.
 *
 *  Re-derives the original nonce from host_commit(rho), adds rho, and normalizes
 *  the resulting nonce to have even Y as BIP340 requires. This stateless API
 *  does not take a previously supplied commitment; an incorrect opening gives a
 *  different original nonce and will be rejected by the host's verification.
 *  The returned signature is verified before success is reported.
 *
 *  Returns 1 on success, or 0 on invalid rho or nonce generation failure
 *  (zeroing sig64). No nonce retry or grinding is performed.
 *  Args:      ctx: a context object, not secp256k1_context_static.
 *  Out:    sig64: the ordinary 64-byte BIP340 signature.
 *  In:     msg32: the 32-byte message being signed.
 *        keypair: the actual signing keypair.
 *          rho32: the host's scalar opening, encoded as 32 big-endian bytes.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_anti_exfil_sign(
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_keypair *keypair,
    const unsigned char *rho32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Verify the signature and its binding to the host's contribution.
 *
 *  Returns 1 iff sig64 is valid under pubkey for msg32 and its public nonce has
 *  the x-coordinate of R0 + rho*G. Returns 0 for invalid rho or an infinity sum.
 *  The signer_nonce must be the original, unmodified R0 received before reveal;
 *  accepting a replacement R0 alongside the signature defeats anti-exfil.
 *  Args:          ctx: a context object.
 *  In:         sig64: an ordinary 64-byte BIP340 signature.
 *              msg32: the exact 32-byte message originally requested.
 *             pubkey: the actual x-only signing public key.
 *              rho32: the host's original random scalar.
 *       signer_nonce: the public nonce received before revealing rho32.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_anti_exfil_host_verify(
    const secp256k1_context *ctx,
    const unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *pubkey,
    const unsigned char *rho32,
    const secp256k1_pubkey *signer_nonce
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ANTI_EXFIL_H */
