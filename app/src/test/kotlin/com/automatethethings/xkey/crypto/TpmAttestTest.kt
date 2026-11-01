/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xKey.
 *
 * xKey is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.ECPublicKey

/**
 * Covers the CA's reading of an attestation quote.
 *
 * The wire result echoes the nonce in a field of its own, which proves nothing:
 * a device that never quoted can copy it back. What proves freshness is the
 * nonce inside the signed TPMS_ATTEST, and what ties the quote to the key being
 * certified is the qualified signer inside it. Both are checked here, along with
 * the signature that makes either meaningful.
 */
class TpmAttestTest {

    private val nonce = ByteArray(32) { (it * 3 + 1).toByte() }

    private class Quote(val quoted: ByteArray, val signature: ByteArray, val iak: TpmPublicArea)

    private fun buildQuote(
        keys: KeyPair = TpmTestStructures.generateEcKeyPair(),
        extraData: ByteArray = nonce,
        signerName: ByteArray? = null,
        signWith: KeyPair = keys,
        magic: Int = TpmAttest.TPM_GENERATED,
        type: Int = TpmAttest.ST_ATTEST_QUOTE
    ): Quote {
        val iak = TpmPublicArea.parse(
            TpmTestStructures.eccPublicArea(
                keys.public as ECPublicKey, TpmTestStructures.IAK_ATTRIBUTES
            )
        )
        val quoted = TpmTestStructures.quoteAttest(
            qualifiedSigner = signerName ?: iak.name(),
            extraData = extraData,
            magic = magic,
            type = type
        )
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(signWith.private)
            update(quoted)
        }.sign()
        return Quote(quoted, signature, iak)
    }

    @Test
    fun `parses the fields a CA reads`() {
        val quote = buildQuote()
        val attest = TpmAttest.parse(quote.quoted)

        assertEquals(TpmAttest.TPM_GENERATED, attest.magic)
        assertEquals(TpmAttest.ST_ATTEST_QUOTE, attest.type)
        assertArrayEquals(nonce, attest.extraData)
        assertArrayEquals(quote.iak.name(), attest.qualifiedSigner)
        assertEquals(32, attest.pcrDigest.size)
    }

    @Test
    fun `accepts a quote signed by the IAK and bound to the nonce`() {
        val quote = buildQuote()
        val attest = TpmQuoteVerifier.verify(quote.iak, quote.quoted, quote.signature, nonce)
        assertArrayEquals(nonce, attest.extraData)
    }

    @Test
    fun `refuses a quote that does not begin with TPM_GENERATED_VALUE`() {
        val quote = buildQuote(magic = 0x11223344)
        expectRefusal(quote, nonce, "TPM_GENERATED_VALUE")
    }

    @Test
    fun `refuses an attestation that is not a quote`() {
        // A certification is a well-formed TPMS_ATTEST; it just attests a key
        // rather than PCR state, so its trailing union is shaped differently.
        val quote = buildQuote(type = TpmAttest.ST_ATTEST_CERTIFY)
        expectRefusal(quote, nonce, "expected 0x8018")
    }

    @Test
    fun `refuses a quote bound to a different nonce`() {
        val quote = buildQuote(extraData = ByteArray(32))
        expectRefusal(quote, nonce, "not bound to the nonce")
    }

    @Test
    fun `refuses a quote whose signer is not the IAK`() {
        val quote = buildQuote(signerName = ByteArray(34) { 0x5A })
        expectRefusal(quote, nonce, "not the IAK")
    }

    @Test
    fun `refuses a quote signed by another key`() {
        val keys = TpmTestStructures.generateEcKeyPair()
        val impostor = TpmTestStructures.generateEcKeyPair()
        val quote = buildQuote(keys = keys, signWith = impostor)
        expectRefusal(quote, nonce, "does not verify")
    }

    @Test
    fun `refuses an empty quote or signature`() {
        val quote = buildQuote()
        expectRefusal(quote.iak, ByteArray(0), quote.signature, "no attestation structure")
        expectRefusal(quote.iak, quote.quoted, ByteArray(0), "no signature")
    }

    @Test
    fun `refuses an IAK that declares no signing scheme`() {
        val keys = TpmTestStructures.generateEcKeyPair()
        val schemeless = TpmPublicArea.parse(
            TpmTestStructures.eccPublicArea(
                keys.public as ECPublicKey,
                TpmTestStructures.IAK_ATTRIBUTES,
                scheme = TpmAlg.NULL
            )
        )
        val quoted = TpmTestStructures.quoteAttest(schemeless.name(), nonce)
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(keys.private)
            update(quoted)
        }.sign()
        expectRefusal(schemeless, quoted, signature, "no signing scheme")
    }

    @Test
    fun `refuses a truncated attestation structure`() {
        val quote = buildQuote()
        try {
            TpmAttest.parse(quote.quoted.copyOfRange(0, 12))
            fail("a truncated quote must not parse")
        } catch (e: TpmQuoteException) {
            assertTrue(e.message != null)
        }
    }

    private fun expectRefusal(quote: Quote, expectedNonce: ByteArray, reason: String) =
        expectRefusal(quote.iak, quote.quoted, quote.signature, reason, expectedNonce)

    private fun expectRefusal(
        iak: TpmPublicArea,
        quoted: ByteArray,
        signature: ByteArray,
        reason: String,
        expectedNonce: ByteArray = nonce
    ) {
        try {
            TpmQuoteVerifier.verify(iak, quoted, signature, expectedNonce)
            fail("expected refusal containing '$reason'")
        } catch (e: TpmQuoteException) {
            assertTrue(
                "expected '$reason' but got '${e.message}'",
                e.message!!.contains(reason)
            )
        }
    }
}
