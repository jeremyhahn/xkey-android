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
package com.automatethethings.xkey.password

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * Unit tests for [PasswordVaultCredential.fromJson]: the exact wire names of
 * go-xkms `transport.PasswordVaultCredential`, and the refusal of malformed
 * bodies, including the retired `{user_pin}` body.
 */
class PasswordVaultCredentialTest {

    private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private fun invalid(json: String?): VaultCredentialInvalidException {
        val params = json?.let { JSONObject(it) }
        return try {
            PasswordVaultCredential.fromJson(params)
            throw AssertionError("expected VaultCredentialInvalidException")
        } catch (e: VaultCredentialInvalidException) {
            e
        }
    }

    @Test
    fun `a passphrase credential parses factor and passphrase`() {
        val credential = PasswordVaultCredential.fromJson(
            JSONObject("""{"factor":"passphrase","passphrase":"correct horse"}""")
        )

        assertTrue(credential is PasswordVaultCredential.Passphrase)
        assertEquals("passphrase", credential.factor)
        assertEquals("correct horse", (credential as PasswordVaultCredential.Passphrase).passphrase)
    }

    @Test
    fun `a passkey credential decodes credential_id and the 32-byte secret`() {
        val id = byteArrayOf(1, 2, 3, 4)
        val secret = ByteArray(32) { it.toByte() }

        val credential = PasswordVaultCredential.fromJson(
            JSONObject("""{"factor":"passkey","credential_id":"${b64(id)}","secret":"${b64(secret)}"}""")
        ) as PasswordVaultCredential.Passkey

        assertEquals("passkey", credential.factor)
        assertArrayEquals(id, credential.credentialId)
        assertArrayEquals(secret, credential.secret)
        assertNull(credential.prfSalt)
    }

    @Test
    fun `a passkey secret that is not 32 bytes is invalid`() {
        val e = invalid("""{"factor":"passkey","credential_id":"${b64(byteArrayOf(1))}","secret":"${b64(ByteArray(16))}"}""")

        assertEquals("secret must be the 32-byte hmac-secret output", e.message)
    }

    @Test
    fun `each key factor parses key_fingerprint and secret`() {
        for (factor in listOf("piv", "certificate", "tpm")) {
            val credential = PasswordVaultCredential.fromJson(
                JSONObject("""{"factor":"$factor","key_fingerprint":"SHA256:abc","secret":"${b64(byteArrayOf(9, 9))}"}""")
            ) as PasswordVaultCredential.Key

            assertEquals(factor, credential.factor)
            assertEquals("SHA256:abc", credential.keyFingerprint)
            assertArrayEquals(byteArrayOf(9, 9), credential.secret)
        }
    }

    @Test
    fun `a key factor without key_fingerprint is invalid`() {
        val e = invalid("""{"factor":"tpm","secret":"${b64(byteArrayOf(1))}"}""")

        assertEquals("key_fingerprint is required", e.message)
    }

    @Test
    fun `the retired user_pin body is invalid`() {
        val e = invalid("""{"user_pin":"123456"}""")

        assertTrue(e.message!!.contains("user_pin"))
        assertFalse("the PIN value must not be echoed", e.message!!.contains("123456"))
    }

    @Test
    fun `a missing body is invalid`() {
        assertEquals("missing credential", invalid(null).message)
    }

    @Test
    fun `a body without a factor is invalid`() {
        assertEquals("factor is required", invalid("""{"passphrase":"x"}""").message)
    }

    @Test
    fun `an unknown factor is invalid`() {
        assertEquals("unknown factor: fido", invalid("""{"factor":"fido"}""").message)
    }

    @Test
    fun `an empty passphrase is invalid`() {
        assertEquals("passphrase is required", invalid("""{"factor":"passphrase","passphrase":""}""").message)
    }

    @Test
    fun `a secret that is not base64 is invalid`() {
        val e = invalid("""{"factor":"piv","key_fingerprint":"fp","secret":"not base64!"}""")

        assertEquals("secret must be base64", e.message)
    }

    @Test
    fun `a non-string field is invalid`() {
        assertEquals("passphrase must be a string", invalid("""{"factor":"passphrase","passphrase":42}""").message)
    }
}
