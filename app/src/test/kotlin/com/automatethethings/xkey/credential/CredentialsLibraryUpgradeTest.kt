/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
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
package com.automatethethings.xkey.credential

import android.content.ComponentName
import android.os.Bundle
import androidx.credentials.CreateCredentialRequest
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.Credential
import androidx.credentials.CredentialOption
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.slot
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Bundle wire format between xKey and relying parties under
 * androidx.credentials 1.6.0 (upgraded from 1.3.0).
 *
 * A passkey request reaches xKey as a Bundle written by the relying party's
 * own copy of the library, at whatever version it ships, and xKey's response
 * goes back the same way. Both sides only agree through the Bundle keys and
 * type strings, so these tests pin them as literals. The parse entry points
 * never throw on a mismatch: they fall back to a `*Custom*` type, which the
 * app's `is`/`as?` checks (CreateCredentialHandler.kt:135,
 * GetCredentialHandler.kt:85,177-178) would silently ignore, so each test
 * also checks the typed class came back.
 *
 * The request tests use the same public parse functions the provider-side
 * library applies to the framework's request (`CreateCredentialRequest`
 * and `CredentialOption.createFrom`); the response tests use the
 * constructors CredentialSelectorActivity calls (:134, :190) and the
 * `createFrom` a relying party's library applies to them.
 */
class CredentialsLibraryUpgradeTest {

    @After
    fun tearDown() {
        unmockkAll()
    }

    /**
     * Turns red if 1.6.0 changed the key or type string a registration
     * response is written under, or tightened its JSON validation so the
     * app's attestation response is rejected (the constructor `require`s
     * `RequestValidationHelper.isValidJSON`).
     */
    @Test
    fun `registration response is written under the key relying parties read`() {
        mockkConstructor(Bundle::class)
        val key = slot<String>()
        val value = slot<String>()
        every { anyConstructed<Bundle>().putString(capture(key), capture(value)) } just Runs

        val response = CreatePublicKeyCredentialResponse(REGISTRATION_RESPONSE_JSON)

        assertEquals(TYPE_PUBLIC_KEY, response.type)
        assertEquals(KEY_REGISTRATION_RESPONSE, key.captured)
        assertEquals(REGISTRATION_RESPONSE_JSON, value.captured)
    }

    /** Turns red if 1.6.0 no longer parses a registration response from that key. */
    @Test
    fun `registration response parses back from the relying party's bundle`() {
        val data = mockk<Bundle>(relaxed = true) {
            every { getString(KEY_REGISTRATION_RESPONSE) } returns REGISTRATION_RESPONSE_JSON
        }

        val parsed = CreateCredentialResponse.createFrom(TYPE_PUBLIC_KEY, data)

        assertTrue(parsed is CreatePublicKeyCredentialResponse)
        assertEquals(
            REGISTRATION_RESPONSE_JSON,
            (parsed as CreatePublicKeyCredentialResponse).registrationResponseJson
        )
    }

    /**
     * Turns red if 1.6.0 changed the key or type string an assertion
     * response is written under, or rejects the app's assertion JSON.
     */
    @Test
    fun `assertion response is written under the key relying parties read`() {
        mockkConstructor(Bundle::class)
        val key = slot<String>()
        val value = slot<String>()
        every { anyConstructed<Bundle>().putString(capture(key), capture(value)) } just Runs

        val credential = PublicKeyCredential(ASSERTION_RESPONSE_JSON)

        assertEquals(TYPE_PUBLIC_KEY, credential.type)
        assertEquals(TYPE_PUBLIC_KEY, PublicKeyCredential.TYPE_PUBLIC_KEY_CREDENTIAL)
        assertEquals(KEY_AUTHENTICATION_RESPONSE, key.captured)
        assertEquals(ASSERTION_RESPONSE_JSON, value.captured)
    }

    /** Turns red if 1.6.0 no longer parses an assertion response from that key. */
    @Test
    fun `assertion response parses back from the relying party's bundle`() {
        val data = mockk<Bundle>(relaxed = true) {
            every { getString(KEY_AUTHENTICATION_RESPONSE) } returns ASSERTION_RESPONSE_JSON
        }

        val parsed = Credential.createFrom(TYPE_PUBLIC_KEY, data)

        assertTrue(parsed is PublicKeyCredential)
        assertEquals(
            ASSERTION_RESPONSE_JSON,
            (parsed as PublicKeyCredential).authenticationResponseJson
        )
    }

    /**
     * Turns red if 1.6.0 reads a registration request's subtype, JSON or
     * client data hash from different keys. A lost hash is the dangerous
     * case: CreateCredentialHandler.kt:174-178 then builds its own
     * clientDataJSON and signs over a hash the browser never sent.
     */
    @Test
    fun `registration request keeps the browser's client data hash`() {
        val clientDataHash = ByteArray(32) { (it + 1).toByte() }

        val parsed = CreateCredentialRequest.createFrom(
            TYPE_PUBLIC_KEY,
            createRequestData(clientDataHash),
            mockk(relaxed = true),
            false,
            null
        )

        assertTrue(parsed is CreatePublicKeyCredentialRequest)
        parsed as CreatePublicKeyCredentialRequest
        assertEquals(CREATE_REQUEST_JSON, parsed.requestJson)
        assertArrayEquals(clientDataHash, parsed.clientDataHash)
    }

    /**
     * Turns red if 1.6.0 stopped reporting an absent hash as null, which is
     * how CreateCredentialHandler.kt:178 knows to build clientDataJSON for
     * an app caller.
     */
    @Test
    fun `registration request without a hash reports none`() {
        val parsed = CreateCredentialRequest.createFrom(
            TYPE_PUBLIC_KEY,
            createRequestData(clientDataHash = null),
            mockk(relaxed = true),
            false,
            null
        )

        assertTrue(parsed is CreatePublicKeyCredentialRequest)
        assertNull((parsed as CreatePublicKeyCredentialRequest).clientDataHash)
    }

    /**
     * Turns red if 1.6.0 reads a sign-in option's subtype, JSON or client
     * data hash from different keys; GetCredentialHandler.kt:177-178 and
     * :201-205 depend on the typed option and its hash.
     */
    @Test
    fun `sign-in option keeps the browser's client data hash`() {
        val clientDataHash = ByteArray(32) { (it + 7).toByte() }
        val requestData = mockk<Bundle>(relaxed = true) {
            every { getString(KEY_SUBTYPE) } returns SUBTYPE_GET_OPTION
            every { getString(KEY_REQUEST_JSON) } returns GET_REQUEST_JSON
            every { getByteArray(KEY_CLIENT_DATA_HASH) } returns clientDataHash
        }

        val parsed = CredentialOption.createFrom(
            TYPE_PUBLIC_KEY,
            requestData,
            mockk(relaxed = true),
            false,
            emptySet<ComponentName>()
        )

        assertTrue(parsed is GetPublicKeyCredentialOption)
        parsed as GetPublicKeyCredentialOption
        assertEquals(GET_REQUEST_JSON, parsed.requestJson)
        assertArrayEquals(clientDataHash, parsed.clientDataHash)
    }

    private fun createRequestData(clientDataHash: ByteArray?): Bundle =
        mockk<Bundle>(relaxed = true) {
            every { getString(KEY_SUBTYPE) } returns SUBTYPE_CREATE_REQUEST
            every { getString(KEY_REQUEST_JSON) } returns CREATE_REQUEST_JSON
            every { getByteArray(KEY_CLIENT_DATA_HASH) } returns clientDataHash
            // No display-info bundle: the library falls back to user.name.
            every { getBundle(any()) } returns null
        }

    private companion object {
        const val TYPE_PUBLIC_KEY = "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
        const val KEY_SUBTYPE = "androidx.credentials.BUNDLE_KEY_SUBTYPE"
        const val KEY_REQUEST_JSON = "androidx.credentials.BUNDLE_KEY_REQUEST_JSON"
        const val KEY_CLIENT_DATA_HASH = "androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH"
        const val KEY_REGISTRATION_RESPONSE =
            "androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON"
        const val KEY_AUTHENTICATION_RESPONSE =
            "androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON"
        const val SUBTYPE_CREATE_REQUEST =
            "androidx.credentials.BUNDLE_VALUE_SUBTYPE_CREATE_PUBLIC_KEY_CREDENTIAL_REQUEST"
        const val SUBTYPE_GET_OPTION =
            "androidx.credentials.BUNDLE_VALUE_SUBTYPE_GET_PUBLIC_KEY_CREDENTIAL_OPTION"

        const val CREATE_REQUEST_JSON = """{"challenge":"dGVzdC1jaGFsbGVuZ2U",""" +
            """"rp":{"id":"webauthn.io","name":"webauthn.io"},""" +
            """"user":{"id":"dXNlci0x","name":"alice","displayName":"Alice"},""" +
            """"pubKeyCredParams":[{"type":"public-key","alg":-7}],""" +
            """"authenticatorSelection":{"residentKey":"required","userVerification":"required"}}"""

        const val GET_REQUEST_JSON = """{"challenge":"dGVzdC1jaGFsbGVuZ2U",""" +
            """"rpId":"webauthn.io","allowCredentials":[],"userVerification":"required"}"""

        /** Shaped like CreateCredentialHandler.buildAttestationResponse output. */
        const val REGISTRATION_RESPONSE_JSON = """{"id":"AAECAw","rawId":"AAECAw",""" +
            """"type":"public-key","authenticatorAttachment":"platform",""" +
            """"response":{"clientDataJSON":"e30","attestationObject":"o2NmbXRkbm9uZQ",""" +
            """"authenticatorData":"SZYN5YgO","publicKeyAlgorithm":-7,""" +
            """"publicKey":"MFkwEwYHKoZI","transports":["internal"]},""" +
            """"clientExtensionResults":{}}"""

        /** Shaped like GetCredentialHandler's assertion response. */
        const val ASSERTION_RESPONSE_JSON = """{"id":"AAECAw","rawId":"AAECAw",""" +
            """"type":"public-key","authenticatorAttachment":"platform",""" +
            """"response":{"clientDataJSON":"e30","authenticatorData":"SZYN5YgO",""" +
            """"signature":"MEUCIQ","userHandle":"dXNlci0x"},""" +
            """"clientExtensionResults":{}}"""
    }
}
