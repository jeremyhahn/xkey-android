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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.MessageDigest

/**
 * The cross-repository byte agreement gate for device attestation protocol v2.
 *
 * Every literal below is copied from the normative vector table on go-xkms#129
 * §8, which go-xkms pins in `xkey/pkg/pairing/attest_vectors_test.go`. The two
 * implementations share no code — a Kotlin app cannot import a Go package — so
 * these vectors are the only thing that holds the wire together.
 *
 * **A failure here is a wire break, never a test to update.** If the desktop
 * changes a byte, the fix is a coordinated change on both sides through
 * agent-company, not a new expected value in this file.
 */
class AttestTranscriptTest {

    // ---- Inputs, go-xkms#129 §8 ------------------------------------------

    private val nonce = ByteArray(32) { it.toByte() }                       // 0x00..0x1f
    private val channelBinding = ByteArray(32) { (0x40 + it).toByte() }     // 0x40..0x5f
    private val deviceFingerprint = ByteArray(32) { (0x80 + it).toByte() }  // 0x80..0x9f
    private val initiatorStatic = ByteArray(32) { 0x11 }
    private val responderStatic = ByteArray(32) { 0x22 }
    private val prologue = ByteArray(32) { 0x33 }

    // ---- Expected outputs, go-xkms#129 §8 --------------------------------

    private val pairTranscriptHex =
        "786b65792d6174746573742d7472616e7363726970742d76310470616972" +
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"

    private val reattestTranscriptHex =
        "786b65792d6174746573742d7472616e7363726970742d7631087265617474657374" +
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"

    /**
     * `local.verifyUser` (owner ruling 167, go-xkms `pkg/pairingproto`
     * `attest_vectors_test.go` at 109f9c16f). The last field is the UVK's
     * fingerprint; the inputs are the same as for pair and reattest.
     */
    private val verifyUserTranscriptHex =
        "786b65792d6174746573742d7472616e7363726970742d76310b7665726966792d75736572" +
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"

    private val verifyUserDigestHex =
        "30f3f98d0ccfa8302dbc2768119257aa0cbf18b5e2391fe8c08a1dca8dd11a04"

    private val channelBindingWithPrologueHex =
        "f6cdd5b309152e44264c49cd523a88c0e9ee18e4e59da14b7278d99dfd16b6b6"

    private val channelBindingNoPrologueHex =
        "53bfe5540b4862f534eb0990978b81d4277f5923d67a7b83be7271801a1bae22"

    /**
     * The same two static keys with the **roles reversed** — initiator `0x22`,
     * responder `0x11`.
     *
     * Part of the normative §8 table — added as a spec addendum (go-xkms
     * `4cfae83d`, #129 comment 15787) after the original two channel-binding
     * vectors were found unable to catch the property they appear to protect.
     *
     * The published inputs use `initiator = 0x11` and `responder = 0x22`, which
     * already sort into the order they are in, so a **role-blind** derivation
     * reproduces `channelBindingWithPrologueHex` exactly and the original table
     * notices nothing. Measured on both sides, and the Go real-path interop test
     * missed it too — both ends call the same derivation, so mutating it moves
     * the oracle along with the subject.
     *
     * Note this differs from `channelBindingWithPrologueHex`, which is the point:
     * a sorted derivation would yield that value for *both* orderings.
     *
     * These values were computed independently here and match go-xkms byte for
     * byte. A change to any of them is a wire break, not a test to update.
     */
    private val channelBindingRoleReversedWithPrologueHex =
        "c3a3a274dde29ad887300714f44bdb804c70722767463cac91ac0b99a0619244"

    private val channelBindingRoleReversedNoPrologueHex =
        "da49360dad9f9f97fc05c1135a18c7905e06bb8ddc156fd3df907665d503b2e6"

    // ---- Domain constants ------------------------------------------------

    @Test
    fun `genesis challenge matches the pinned constant`() {
        assertEquals(
            "786b65792d6465766963652d6174746573746174696f6e2d7631",
            AttestTranscript.GENESIS_CHALLENGE.toHex()
        )
        assertEquals(26, AttestTranscript.GENESIS_CHALLENGE.size)
    }

    // ---- Transcript vectors ----------------------------------------------

    @Test
    fun `pair transcript matches the cross-repo vector byte for byte`() {
        val transcript = AttestTranscript.build(
            AttestTranscript.PURPOSE_PAIR, nonce, channelBinding, deviceFingerprint
        )
        assertEquals(126, transcript.size)
        assertEquals(pairTranscriptHex, transcript.toHex())
    }

    @Test
    fun `reattest transcript matches the cross-repo vector byte for byte`() {
        val transcript = AttestTranscript.build(
            AttestTranscript.PURPOSE_REATTEST, nonce, channelBinding, deviceFingerprint
        )
        assertEquals(130, transcript.size)
        assertEquals(reattestTranscriptHex, transcript.toHex())
    }

    @Test
    fun `verify-user transcript matches the cross-repo vector byte for byte`() {
        val transcript = AttestTranscript.build(
            AttestTranscript.PURPOSE_VERIFY_USER, nonce, channelBinding, deviceFingerprint
        )
        assertEquals(133, transcript.size)
        assertEquals(verifyUserTranscriptHex, transcript.toHex())
        assertEquals(verifyUserDigestHex, sha256(transcript).toHex())
    }

    @Test
    fun `verify-user purpose matches the pinned constant`() {
        assertEquals(
            "7665726966792d75736572",
            AttestTranscript.PURPOSE_VERIFY_USER.toByteArray(Charsets.US_ASCII).toHex()
        )
    }

    /** The UVK's attestation challenge: the constant alone, no trailing bytes. */
    @Test
    fun `user verification challenge matches the pinned constant`() {
        assertEquals(
            "786b65792d757365722d766572696669636174696f6e2d7631",
            AttestTranscript.USER_VERIFICATION_CHALLENGE.toHex()
        )
        assertEquals(25, AttestTranscript.USER_VERIFICATION_CHALLENGE.size)
    }

    // ---- Channel binding vectors -----------------------------------------

    @Test
    fun `channel binding with a reconnect prologue matches the cross-repo vector`() {
        assertEquals(
            channelBindingWithPrologueHex,
            AttestTranscript.channelBinding(initiatorStatic, responderStatic, prologue).toHex()
        )
    }

    @Test
    fun `channel binding for a first pairing matches the cross-repo vector`() {
        assertEquals(
            channelBindingNoPrologueHex,
            AttestTranscript.channelBinding(initiatorStatic, responderStatic, ByteArray(0)).toHex()
        )
    }

    // ---- The properties each field is there to provide -------------------

    /**
     * Reversing the roles must produce a different binding, and specifically
     * *these* bytes — a vector, so a future implementer who only has the table
     * cannot ship a role-blind derivation and see green.
     */
    @Test
    fun `channel binding with the roles reversed matches the cross-repo vector`() {
        assertEquals(
            channelBindingRoleReversedWithPrologueHex,
            AttestTranscript.channelBinding(responderStatic, initiatorStatic, prologue).toHex()
        )
        assertEquals(
            channelBindingRoleReversedNoPrologueHex,
            AttestTranscript.channelBinding(responderStatic, initiatorStatic, ByteArray(0)).toHex()
        )
    }

    // ---- Refusals: a malformed transcript must never be signed -----------

    @Test
    fun `an unknown purpose is refused`() {
        assertThrows(IllegalArgumentException::class.java) {
            AttestTranscript.build("enroll", nonce, channelBinding, deviceFingerprint)
        }
    }

    @Test
    fun `a short nonce is refused`() {
        assertThrows(IllegalArgumentException::class.java) {
            AttestTranscript.build(
                AttestTranscript.PURPOSE_PAIR, ByteArray(16), channelBinding, deviceFingerprint
            )
        }
    }

    @Test
    fun `a hex-encoded fingerprint is refused`() {
        val hexForm = deviceFingerprint.toHex().toByteArray(Charsets.US_ASCII)
        assertThrows(IllegalArgumentException::class.java) {
            AttestTranscript.build(
                AttestTranscript.PURPOSE_PAIR, nonce, channelBinding, hexForm
            )
        }
    }

    @Test
    fun `a prologue that is neither empty nor 32 bytes is refused`() {
        assertThrows(IllegalArgumentException::class.java) {
            AttestTranscript.channelBinding(initiatorStatic, responderStatic, ByteArray(16))
        }
    }

    @Test
    fun `a short static key is refused`() {
        assertThrows(IllegalArgumentException::class.java) {
            AttestTranscript.channelBinding(ByteArray(31), responderStatic, prologue)
        }
    }

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
