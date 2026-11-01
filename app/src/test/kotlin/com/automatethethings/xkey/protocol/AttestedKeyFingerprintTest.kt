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
import org.junit.Test

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
}
