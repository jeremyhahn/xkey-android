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

import com.automatethethings.xkey.truststore.TestCertificates
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import java.security.MessageDigest

/**
 * Pins the #93 / go-xkms PR #124 flag-day wire value: the per-device pairing
 * fingerprint the phone echoes on reconnect is `SHA-256` of the attested leaf
 * certificate's `SubjectPublicKeyInfo`.
 *
 * These are cross-repository TEST VECTORS. go-xkms derives the desktop-side
 * value as `sha256(cert.RawSubjectPublicKeyInfo)` over the SAME leaf; hashing
 * the same fixture certificate on both sides is the byte-for-byte agreement
 * check that gates the atomic co-merge. If either side's derivation drifts, the
 * pinned hex below changes and this test goes red.
 */
class AttestedKeyFingerprintTest {

    // ---- Frozen cross-platform test vectors -------------------------------
    // SHA-256 of each fixture leaf's DER SubjectPublicKeyInfo. Reproduce with:
    //   openssl x509 -in leaf.pem -noout -pubkey | openssl pkey -pubin \
    //     -outform DER | openssl dgst -sha256
    // and cross-check on the Go side with
    //   sha256.Sum256(cert.RawSubjectPublicKeyInfo).

    /** StrongBox leaf (`device-sb.xkey.test`) — mirrors the interop gate leaf. */
    private val strongBoxLeafVector =
        "072fd88a135530275c4882683429886b017b29320f5684e78e741afd055dcf60"

    /** Hierarchy-A leaf (`device-a.xkey.test`). */
    private val leafAVector =
        "1b7fc22ba4ed70515f6a12e9bf1424551a08ffb063433ceb7d323c5900781b1d"

    @Test
    fun `strongbox leaf SPKI matches the frozen cross-platform vector`() {
        val der = TestCertificates.der(TestCertificates.LEAF_C_PEM)
        assertEquals(strongBoxLeafVector, AttestedKeyFingerprint.hexOf(der))
    }

    @Test
    fun `hierarchy-A leaf SPKI matches the frozen cross-platform vector`() {
        val der = TestCertificates.der(TestCertificates.LEAF_A_PEM)
        assertEquals(leafAVector, AttestedKeyFingerprint.hexOf(der))
    }

    @Test
    fun `of returns 32 raw bytes whose hex is hexOf`() {
        val der = TestCertificates.der(TestCertificates.LEAF_C_PEM)
        val raw = AttestedKeyFingerprint.of(der)
        assertEquals("the echoed identity-ack fingerprint is 32 bytes", 32, raw.size)
        assertEquals(
            AttestedKeyFingerprint.hexOf(der),
            raw.joinToString("") { "%02x".format(it) }
        )
    }

    @Test
    fun `it hashes the SPKI, not the whole leaf DER nor the root`() {
        val leafDer = TestCertificates.der(TestCertificates.LEAF_C_PEM)
        val rootDer = TestCertificates.der(TestCertificates.ROOT_CA_C_STRONGBOX_PEM)

        val fp = AttestedKeyFingerprint.hexOf(leafDer)
        assertNotEquals("must not be the SHA-256 of the whole leaf DER", sha256Hex(leafDer), fp)
        assertNotEquals("must not be the SHA-256 of the whole root DER (the old value)", sha256Hex(rootDer), fp)
        assertNotEquals("must not be the leaf-SPKI hash of a different device", AttestedKeyFingerprint.hexOf(TestCertificates.der(TestCertificates.LEAF_A_PEM)), fp)
    }

    @Test
    fun `it equals the SHA-256 of the JCA-encoded SubjectPublicKeyInfo`() {
        // For the P-256 named-curve keys Android attestation uses, the
        // certificate's SPKI is already canonical DER, so JCA's re-encoded
        // publicKey.encoded is byte-identical to the certificate's own SPKI and
        // to Go's RawSubjectPublicKeyInfo. This documents that equivalence and
        // fires loudly if a provider ever re-encodes EC parameters differently.
        val cert = TestCertificates.cert(TestCertificates.LEAF_C_PEM)
        val jcaSpkiHash = sha256Hex(cert.publicKey.encoded)
        assertEquals(jcaSpkiHash, AttestedKeyFingerprint.hexOf(cert.encoded))
    }

    @Test
    fun `re-attesting the same key yields the same fingerprint`() {
        // Stability property #93 relies on: the value is a function of the key,
        // so the same leaf (or any re-issue certifying the same key) is stable.
        val der = TestCertificates.der(TestCertificates.LEAF_C_PEM)
        assertEquals(AttestedKeyFingerprint.hexOf(der), AttestedKeyFingerprint.hexOf(der))
    }

    private fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
}
