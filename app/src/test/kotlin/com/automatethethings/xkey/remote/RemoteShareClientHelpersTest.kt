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
package com.automatethethings.xkey.remote

import com.automatethethings.xkey.ca.DeviceIdentity
import com.automatethethings.xkey.crypto.DeviceAttestationKey
import com.automatethethings.xkey.crypto.FileEncryptor
import com.automatethethings.xkey.crypto.KeystoreUserVerificationKey
import com.automatethethings.xkey.protocol.ProtocolException
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.Base64

class RemoteShareClientHelpersTest {

    private val client = RemoteShareClient

    private fun encode(params: JSONObject, field: String, secret: ByteArray): ByteArray =
        client.encodeWithSecret(7L, "remote.shareSymmetric", params, field, secret)

    private fun occurrences(haystack: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty()) return 0
        var count = 0
        var i = 0
        while (i <= haystack.size - needle.size) {
            var match = true
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) { match = false; break }
            }
            if (match) count++
            i++
        }
        return count
    }

    private fun assertRoundTrip(params: JSONObject, field: String, secret: ByteArray) {
        val expectedParams = JSONObject(params.toString())
        val out = encode(params, field, secret)
        val obj = JSONObject(String(out, Charsets.UTF_8))
        assertEquals(7L, obj.getLong("id"))
        assertEquals("remote.shareSymmetric", obj.getString("method"))
        val got = obj.getJSONObject("params")
        val b64 = Base64.getEncoder().encodeToString(secret)
        assertEquals(b64, got.getString(field))
        got.remove(field)
        assertEquals(expectedParams.toMap(), got.toMap())
        if (b64.isNotEmpty()) assertEquals(1, occurrences(out, b64.toByteArray(Charsets.US_ASCII)))
    }

    private fun malformed(block: () -> Unit) {
        val e = assertThrows(ProtocolException::class.java) { block() }
        assertTrue(e.message, e.message!!.startsWith("Malformed share reply: "))
    }

    // encodeWithSecret

    @Test
    fun `encodeWithSecret with empty params parses as the request plus the field`() {
        assertRoundTrip(JSONObject(), "key", byteArrayOf(1, 2, 3, 4))
    }

    @Test
    fun `encodeWithSecret with params keeps every param and adds the field`() {
        val params = JSONObject().put("key_id", "k1").put("algorithm", "AES-256-GCM").put("size", 256)
        assertRoundTrip(params, "key", ByteArray(32) { it.toByte() })
    }

    @Test
    fun `encodeWithSecret with an empty secret writes an empty string`() {
        assertRoundTrip(JSONObject().put("key_id", "k1"), "key", ByteArray(0))
        assertRoundTrip(JSONObject(), "key", ByteArray(0))
    }

    @Test
    fun `encodeWithSecret carries every byte value`() {
        val secret = ByteArray(256) { it.toByte() }
        assertRoundTrip(JSONObject().put("key_id", "k1"), "key", secret)
        val obj = JSONObject(String(encode(JSONObject(), "key", secret), Charsets.UTF_8))
        assertArrayEquals(secret, Base64.getDecoder().decode(obj.getJSONObject("params").getString("key")))
    }

    @Test
    fun `encodeWithSecret leaves the caller's secret untouched`() {
        val secret = ByteArray(16) { (it + 1).toByte() }
        encode(JSONObject(), "key", secret)
        assertArrayEquals(ByteArray(16) { (it + 1).toByte() }, secret)
    }

    @Test
    fun `encodeWithSecret escapes a field name holding a quote or backslash`() {
        assertRoundTrip(JSONObject(), "a\"b", byteArrayOf(1, 2, 3))
        assertRoundTrip(JSONObject().put("key_id", "k1"), "c\\d", byteArrayOf(4, 5, 6))
        assertRoundTrip(JSONObject().put("key_id", "k1"), "e\",\"key_id\":\"x", byteArrayOf(7))
    }

    @Test
    fun `encodeWithSecret refuses a field the params already hold`() {
        val params = JSONObject().put("key", "plain")
        assertThrows(IllegalArgumentException::class.java) { encode(params, "key", byteArrayOf(1, 2)) }
    }

    // parseShareResult

    private fun shareResult() = JSONObject().put("accepted", true).put("import_id", "imp-1").put("backend", "software")

    @Test
    fun `parseShareResult reads a complete reply`() {
        assertEquals(RemoteShareClient.ShareResult(true, "imp-1", "software"), client.parseShareResult(shareResult()))
    }

    @Test
    fun `parseShareResult rejects each field missing, null or of the wrong type`() {
        val wrong = mapOf<String, List<Any>>(
            "accepted" to listOf("true", 1, JSONObject()),
            "import_id" to listOf(1, true, JSONObject()),
            "backend" to listOf(1, false, org.json.JSONArray())
        )
        for ((field, values) in wrong) {
            malformed { client.parseShareResult(shareResult().apply { remove(field) }) }
            malformed { client.parseShareResult(shareResult().put(field, JSONObject.NULL)) }
            for (v in values) malformed { client.parseShareResult(shareResult().put(field, v)) }
        }
    }

    @Test
    fun `parseShareResult accepts a declined reply with an empty import id`() {
        val r = client.parseShareResult(shareResult().put("accepted", false).put("import_id", ""))
        assertEquals(RemoteShareClient.ShareResult(false, "", "software"), r)
    }

    @Test
    fun `parseShareResult rejects an accepted reply with an empty import id`() {
        malformed { client.parseShareResult(shareResult().put("import_id", "")) }
    }

    @Test
    fun `parseShareResult ignores unknown fields`() {
        val r = client.parseShareResult(shareResult().put("extra", JSONObject().put("x", 1)).put("n", 5))
        assertEquals(RemoteShareClient.ShareResult(true, "imp-1", "software"), r)
    }

    // parseImportedKey

    private fun imported() = JSONObject().put("algorithm", "ES256").put("key_type", "signing").put("exportable", false)

    @Test
    fun `parseImportedKey reads key_size absent or null as zero`() {
        assertEquals(0, client.parseImportedKey(imported()).keySize)
        assertEquals(0, client.parseImportedKey(imported().put("key_size", JSONObject.NULL)).keySize)
        assertEquals(0, client.parseImportedKey(imported().put("key_size", 0)).keySize)
        assertEquals(256, client.parseImportedKey(imported().put("key_size", 256)).keySize)
    }

    @Test
    fun `parseImportedKey rejects a long, double or string key_size`() {
        malformed { client.parseImportedKey(imported().put("key_size", Long.MAX_VALUE)) }
        malformed { client.parseImportedKey(JSONObject(imported().toString().dropLast(1) + ",\"key_size\":4294967296}")) }
        malformed { client.parseImportedKey(imported().put("key_size", 256.5)) }
        malformed { client.parseImportedKey(imported().put("key_size", "256")) }
    }

    @Test
    fun `parseImportedKey rejects a negative key_size`() {
        malformed { client.parseImportedKey(imported().put("key_size", -1)) }
        malformed { client.parseImportedKey(imported().put("key_size", Int.MIN_VALUE)) }
    }

    @Test
    fun `parseImportedKey reads an empty wrapped_key as a zero-length array`() {
        val k = client.parseImportedKey(imported().put("wrapped_key", ""))
        assertArrayEquals(ByteArray(0), k.wrappedKey)
    }

    @Test
    fun `parseImportedKey rejects whitespace and url-safe base64`() {
        malformed { client.parseImportedKey(imported().put("wrapped_key", "AAEC AwQF")) }
        malformed { client.parseImportedKey(imported().put("wrapped_key", "AAECAwQF\n")) }
        malformed { client.parseImportedKey(imported().put("wrapped_key", "-_-_")) }
        malformed { client.parseImportedKey(imported().put("public_key_pem", "-_-_")) }
        malformed { client.parseImportedKey(imported().put("wrapped_key", 5)) }
    }

    @Test
    fun `parseImportedKey decodes non UTF-8 PEM bytes with replacement characters`() {
        val bad = Base64.getEncoder().encodeToString(byteArrayOf(0xC3.toByte(), 0x28, 0xFF.toByte()))
        val k = client.parseImportedKey(imported().put("public_key_pem", bad).put("certificate_pem", bad))
        assertTrue(k.publicKeyPem!!.contains('�'))
        assertTrue(k.certificatePem!!.contains('�'))
    }

    @Test
    fun `parseImportedKey returns both a public key and a wrapped key when both are present`() {
        val pem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
        val k = client.parseImportedKey(
            imported()
                .put("public_key_pem", Base64.getEncoder().encodeToString(pem.toByteArray()))
                .put("wrapped_key", Base64.getEncoder().encodeToString(byteArrayOf(9, 8, 7)))
        )
        assertEquals(pem, k.publicKeyPem)
        assertArrayEquals(byteArrayOf(9, 8, 7), k.wrappedKey)
        assertNull(k.certificatePem)
    }

    @Test
    fun `parseImportedKey requires algorithm, key_type and exportable`() {
        for (field in listOf("algorithm", "key_type", "exportable")) {
            malformed { client.parseImportedKey(imported().apply { remove(field) }) }
            malformed { client.parseImportedKey(imported().put(field, JSONObject.NULL)) }
        }
    }

    // DesktopShareGate ids

    @Test
    fun `identity prefix and the user verification alias are identity keys`() {
        assertTrue(DesktopShareGate.isIdentityKey(DeviceIdentity.ALIAS_PREFIX + "1"))
        assertTrue(DesktopShareGate.isIdentityKey(DeviceIdentity.ALIAS_PREFIX))
        assertTrue(DesktopShareGate.isIdentityKey(KeystoreUserVerificationKey.ALIAS))
    }

    @Test
    fun `the device attestation key is an identity key`() {
        assertTrue(DesktopShareGate.isIdentityKey(DeviceAttestationKey.ALIAS))
        assertFalse(DesktopShareGate.isIdentityKey(DeviceAttestationKey.ALIAS.uppercase()))
        assertFalse(DesktopShareGate.isIdentityKey(DeviceAttestationKey.ALIAS + " "))
    }

    @Test
    fun `identity checks are exact and case sensitive`() {
        assertFalse(DesktopShareGate.isIdentityKey(DeviceIdentity.ALIAS_PREFIX.uppercase() + "1"))
        assertFalse(DesktopShareGate.isIdentityKey(" " + DeviceIdentity.ALIAS_PREFIX + "1"))
        assertFalse(DesktopShareGate.isIdentityKey(KeystoreUserVerificationKey.ALIAS + "_2"))
        assertFalse(DesktopShareGate.isIdentityKey(KeystoreUserVerificationKey.ALIAS + " "))
        assertFalse(DesktopShareGate.isIdentityKey(KeystoreUserVerificationKey.ALIAS.uppercase()))
        assertFalse(DesktopShareGate.isIdentityKey(""))
        assertFalse(DesktopShareGate.isIdentityKey("signing-key"))
    }

    @Test
    fun `ephemeral prefix ids are ephemeral keys`() {
        assertTrue(DesktopShareGate.isEphemeralKey(FileEncryptor.EPHEMERAL_KEY_PREFIX + "0b7c"))
        assertTrue(DesktopShareGate.isEphemeralKey(FileEncryptor.EPHEMERAL_KEY_PREFIX))
        assertFalse(DesktopShareGate.isEphemeralKey(FileEncryptor.EPHEMERAL_KEY_PREFIX.uppercase() + "x"))
        assertFalse(DesktopShareGate.isEphemeralKey(" " + FileEncryptor.EPHEMERAL_KEY_PREFIX + "x"))
        assertFalse(DesktopShareGate.isEphemeralKey(""))
        assertFalse(DesktopShareGate.isEphemeralKey("key-ephemeral"))
    }

    @Test
    fun `the keystore alias form of an ephemeral key is not an ephemeral id`() {
        // Discovery strips the xkey_key_ alias prefix before it makes a key id.
        assertFalse(DesktopShareGate.isEphemeralKey("xkey_key_" + FileEncryptor.EPHEMERAL_KEY_PREFIX + "x"))
        assertFalse(DesktopShareGate.isIdentityKey("xkey_key_" + FileEncryptor.EPHEMERAL_KEY_PREFIX + "x"))
    }
}
