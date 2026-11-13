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
package com.automatethethings.xkey.ui

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * The QR import path the activity runs after a scan decodes: payload text to
 * the stored contact row, without the camera.
 */
class ContactImportCandidateTest {

    private fun ecDer(curve: String): ByteArray =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }
            .generateKeyPair().public.encoded

    private fun pem(der: ByteArray): String =
        "-----BEGIN PUBLIC KEY-----\n" +
            Base64.getEncoder().encodeToString(der).chunked(64).joinToString("\n") +
            "\n-----END PUBLIC KEY-----\n"

    private fun envelope(der: ByteArray, algorithm: String): String =
        JSONObject()
            .put("type", "xkey-contact")
            .put("v", 1)
            .put("label", "Alice's Key")
            .put("algorithm", algorithm)
            .put("key_id", "key-1234")
            .put("public_key_pem", pem(der))
            .toString()

    private fun sha256Hex(der: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) }

    /** The scan's import, named as the prompt pre-fills it: the row the activity stores. */
    private fun importScanned(raw: String) =
        ContactImportCandidate.fromScannedPayload(raw)?.let { candidate ->
            candidate.toEntity(
                name = candidate.suggestedName ?: "Contact",
                source = "qr",
                importedAt = 1_000L
            )
        }

    @Test
    fun qrEnvelopeWithP384KeyAndEs256HintStoresEs384() {
        val der = ecDer("secp384r1")
        val stored = importScanned(envelope(der, "ES256"))
        assertNotNull("envelope was refused", stored)
        assertEquals("ES384", stored!!.algorithm)
        assertEquals("Alice's Key", stored.name)
        assertEquals("qr", stored.source)
        assertArrayEquals(der, stored.publicKeyDer)
        assertEquals(sha256Hex(der), stored.publicKeyFingerprint)
    }

    @Test
    fun qrEnvelopeWithMatchingHintKeepsIt() {
        val stored = importScanned(envelope(ecDer("secp256r1"), "ES256"))
        assertEquals("ES256", stored?.algorithm)
    }

    @Test
    fun bareQrPemPayloadStoresTheDetectedAlgorithm() {
        val stored = importScanned(pem(ecDer("secp521r1")))
        assertEquals("ES512", stored?.algorithm)
    }

    @Test
    fun qrEnvelopeWithUnreadableKeyIsRefused() {
        val text = JSONObject()
            .put("type", "xkey-contact")
            .put("algorithm", "ES256")
            .put("public_key_pem", "-----BEGIN PUBLIC KEY-----\n!!not*base64~~\n-----END PUBLIC KEY-----\n")
            .toString()
        assertNull(ContactImportCandidate.fromScannedPayload(text))
    }

    @Test
    fun fileImportBytesIgnoreADisagreeingHint() {
        val candidate = ContactImportCandidate.fromBytes(ecDer("secp384r1"), algorithmHint = "ES256")
        assertEquals("ES384", candidate?.algorithm)
    }
}
