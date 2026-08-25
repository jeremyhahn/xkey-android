/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.protocol

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * The byte layouts of device attestation protocol **version 2** — the
 * challenge-response model ruled by the owner on 2026-08-24 (go-xkms#129).
 *
 * Version 1 asked this device to mint a key whose Android attestation challenge
 * *was* the pairing nonce, and the desktop compared that nonce against the
 * challenge sealed inside the signed leaf. Keystore fixes the attestation
 * challenge at key **generation** and exposes no re-attest-an-existing-key call,
 * so a per-pairing challenge forced a per-pairing key: a stable device identity
 * and embedded-challenge freshness are mutually exclusive on this platform.
 *
 * Version 2 splits the two apart. Identity is a persistent Device Attestation
 * Key ([com.automatethethings.xkey.crypto.DeviceAttestationKey]), attested once
 * against a fixed genesis challenge; freshness is a live ECDSA signature by that
 * same key over [build]'s transcript, which commits to the verifier's nonce, the
 * purpose of the exchange, the channel it is running on, and the identity being
 * claimed.
 *
 * ## Why this object is pure
 *
 * Every byte here has to match `go-xkms/xkey/pkg/pairing/attest_challenge.go`
 * exactly — a disagreement at any offset is a wire break, not a bug to paper
 * over. Keeping the layouts free of Android types lets the cross-repo vectors
 * pinned in `AttestTranscriptTest` run as plain JVM unit tests, so the same code
 * the handler signs with is the code the vectors check.
 *
 * Normative spec: go-xkms issue #129 and
 * `software/docs/12-xkey-android-wire-contract.md`.
 */
object AttestTranscript {

    /** The only device attestation protocol version this build speaks. */
    const val PROTOCOL_VERSION = 2

    /** First pairing: the desktop has no record of this device yet. */
    const val PURPOSE_PAIR = "pair"

    /** Reconnect or an explicit re-attest of a device already on record. */
    const val PURPOSE_REATTEST = "reattest"

    /** Length of the nonce, channel binding and device fingerprint, in bytes. */
    const val BINDING_SIZE = 32

    /**
     * Domain separator for the signed transcript, 25 bytes ASCII. Keeps a DAK
     * signature gathered here from ever being read as a signature for some other
     * use of the same key.
     */
    private val TRANSCRIPT_DOMAIN = "xkey-attest-transcript-v1".toByteArray(Charsets.US_ASCII)

    /** Domain separator for the channel binding derivation, 22 bytes ASCII. */
    private val CHANNEL_DOMAIN = "xkey-attest-channel-v1".toByteArray(Charsets.US_ASCII)

    /**
     * The prefix every Device Attestation Key is born attesting, 26 bytes ASCII.
     *
     * The challenge sealed into the DAK's leaf is this device's *genesis*, not a
     * live nonce — it can never equal the value a verifier draws for a session,
     * which is why the verifier leaves its `ExpectedNonce` unset and checks this
     * prefix instead. Trailing bytes are reserved for install-unique material; a
     * prover that has nothing to add sends exactly this constant, as we do.
     */
    val GENESIS_CHALLENGE = "xkey-device-attestation-v1".toByteArray(Charsets.US_ASCII)

    /**
     * The bytes signed by the Device Attestation Key for one attestation
     * exchange:
     *
     * ```
     * "xkey-attest-transcript-v1"   25 bytes ASCII
     * len8(purpose)                  1 byte
     * purpose                        "pair" | "reattest", ASCII
     * nonce                         32 bytes, drawn by the verifier
     * channelBinding                32 bytes, derived locally by [channelBinding]
     * deviceFingerprint             32 raw bytes, NOT hex
     * ```
     *
     * 126 bytes for `pair`, 130 for `reattest`.
     *
     * The single-byte length in front of [purpose] is not decoration: without it
     * `("pair", nonce)` and `("pairX", nonce')` can serialize identically, and a
     * signature that means one thing becomes a signature for the other.
     *
     * [channelBinding] must be the value **this device derived from its own Noise
     * session** ([channelBinding]). The request carries no channel binding to
     * copy: an earlier draft sent the desktop's own value for diagnostics, and it
     * was removed from the wire precisely so that echoing it is structurally
     * impossible rather than merely forbidden. A prover that echoed it would
     * produce a signature the verifier **accepts** while having committed to no
     * session of its own, and the verifier could not tell.
     *
     * @throws IllegalArgumentException if any input is the wrong length or
     *   [purpose] is not one this protocol defines — a malformed transcript must
     *   never be signed, because the signature would still be valid over
     *   something.
     */
    fun build(
        purpose: String,
        nonce: ByteArray,
        channelBinding: ByteArray,
        deviceFingerprint: ByteArray,
    ): ByteArray {
        require(purpose == PURPOSE_PAIR || purpose == PURPOSE_REATTEST) {
            "unknown attestation purpose '$purpose'"
        }
        require(nonce.size == BINDING_SIZE) { "nonce must be $BINDING_SIZE bytes, got ${nonce.size}" }
        require(channelBinding.size == BINDING_SIZE) {
            "channel binding must be $BINDING_SIZE bytes, got ${channelBinding.size}"
        }
        require(deviceFingerprint.size == BINDING_SIZE) {
            "device fingerprint must be $BINDING_SIZE raw bytes, got ${deviceFingerprint.size}"
        }

        val purposeBytes = purpose.toByteArray(Charsets.US_ASCII)
        val out = ByteArrayOutputStream(
            TRANSCRIPT_DOMAIN.size + 1 + purposeBytes.size + BINDING_SIZE * 3
        )
        out.write(TRANSCRIPT_DOMAIN)
        out.write(purposeBytes.size)
        out.write(purposeBytes)
        out.write(nonce)
        out.write(channelBinding)
        out.write(deviceFingerprint)
        return out.toByteArray()
    }

    /**
     * The 32-byte anti-relay channel binding for the Noise session this
     * attestation is running over:
     *
     * ```
     * SHA-256( "xkey-attest-channel-v1"
     *        || 0x20 || initiatorStaticPublicKey
     *        || 0x20 || responderStaticPublicKey
     *        || len8(prologue) || prologue )
     * ```
     *
     * The **initiator is the xkey desktop and the responder is this phone**,
     * always in that order: "mine then theirs" would give the two ends different
     * values and nothing would ever verify.
     *
     * [prologue] is the Noise prologue the session actually ran under —
     * `SHA-256(initiatorStatic || deviceFingerprintRaw || "xkey-v1")` on a
     * reconnect, and empty on a first pairing, where the desktop has no
     * fingerprint to bind yet. It is length-prefixed so the two cases cannot
     * collide.
     *
     * The threat this closes: an attacker completes its *own* Noise session with
     * the desktop and forwards the desktop's challenge to a genuine phone over a
     * second session. Signing a binding derived from the phone's own session
     * means the relayed signature commits to the wrong pair of static keys, and
     * producing the right one would need both ends' private keys — which the XX
     * handshake proves the attacker does not hold.
     *
     * @throws IllegalArgumentException if a static key is not 32 bytes or the
     *   prologue is neither empty nor 32 bytes.
     */
    fun channelBinding(
        initiatorStaticPublicKey: ByteArray,
        responderStaticPublicKey: ByteArray,
        prologue: ByteArray,
    ): ByteArray {
        require(initiatorStaticPublicKey.size == BINDING_SIZE) {
            "initiator static key must be $BINDING_SIZE bytes, got ${initiatorStaticPublicKey.size}"
        }
        require(responderStaticPublicKey.size == BINDING_SIZE) {
            "responder static key must be $BINDING_SIZE bytes, got ${responderStaticPublicKey.size}"
        }
        require(prologue.isEmpty() || prologue.size == BINDING_SIZE) {
            "prologue must be empty or $BINDING_SIZE bytes, got ${prologue.size}"
        }

        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(CHANNEL_DOMAIN)
        digest.update(initiatorStaticPublicKey.size.toByte())
        digest.update(initiatorStaticPublicKey)
        digest.update(responderStaticPublicKey.size.toByte())
        digest.update(responderStaticPublicKey)
        digest.update(prologue.size.toByte())
        digest.update(prologue)
        return digest.digest()
    }
}
