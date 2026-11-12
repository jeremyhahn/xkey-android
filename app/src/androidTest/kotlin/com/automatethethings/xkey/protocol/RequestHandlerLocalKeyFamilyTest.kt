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

import android.content.Context
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * The `local.*` key-management family, driven directly against
 * [RequestHandler] rather than over a socket.
 *
 * `ProtocolIntegrationTest` proves the round trips a paired desktop performs;
 * [RequestHandlerErrorPathTest] proves the refusals. What is left — and what
 * this suite covers — are the request *shapes* that neither drives:
 *
 * - `local.listKeys` with the `keyType` and `source` filters go-xkms sends
 *   (`xkey device keys --type`), including both at once. Unfiltered listing is
 *   a different query path entirely.
 * - `local.deleteKey` addressed by the legacy `credentialId` rather than
 *   go-xkms's `keyId` — the compatibility alias.
 * - `local.setKeyPolicy`, which the desktop uses to grant sharing after the
 *   fact.
 * - `local.decrypt`, the RSA-OAEP path: no other suite generates an RSA key,
 *   so nothing reached it.
 * - `local.hmac` against a software-backed key, which bypasses the Keystore
 *   entirely and MACs the raw material.
 * - `local.generateKey` for a FIDO2 key (which also emits a COSE public key and
 *   an audit record) and for the 512-bit software HMAC size.
 *
 * Every key is per-run and removed in [tearDown]; other suites assert on empty
 * or exactly-counted stores.
 */
@RunWith(AndroidJUnit4::class)
class RequestHandlerLocalKeyFamilyTest {

    companion object {
        private lateinit var context: Context
        private lateinit var handler: RequestHandler
        private lateinit var softwareKeys: SoftwareKeyStore

        /** Unique per run so nothing collides with a previous run's leftovers. */
        private val runId = System.currentTimeMillis().toString(36)

        /** Source token this suite tags its filter fixtures with. */
        private val filterSource = "keyfamily-$runId"

        private val nextRequestId = AtomicLong(1)

        /** Every key id this suite persists, torn down in [tearDown]. */
        private val createdKeyIds = mutableSetOf<String>()

        @JvmStatic
        @BeforeClass
        fun setUp() {
            context = ApplicationProvider.getApplicationContext()
            softwareKeys = SoftwareKeyStore(context)
            handler = RequestHandler(
                context = context,
                keystoreManager = KeystoreManager(context),
                biometricLauncher = null,
                sessionAuthManager = SessionAuthManager()
            )
        }

        @JvmStatic
        @AfterClass
        fun tearDown() {
            runBlocking {
                val db = XKeyDatabase.getInstance(context)
                val keystoreManager = KeystoreManager(context)

                val ids = createdKeyIds.toMutableSet()
                for (entity in db.keyDao().getAll()) {
                    if (entity.keyId.contains(runId)) ids.add(entity.keyId)
                }
                for (keyId in ids) {
                    runCatching { keystoreManager.deleteGeneralKey(keyId) }
                    runCatching { softwareKeys.delete(keyId) }
                    runCatching { db.keyDao().deleteByKeyId(keyId) }
                }
            }
        }
    }

    /** Headless baseline: no UI, so no biometric prompt is reachable. */
    @Before
    fun resetHandlerState() {
        handler.setSessionId(null)
        handler.setMessageSender(null)
        handler.setActivity(null)
        handler.updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.DISABLED,
                attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
            )
        )
    }

    // ------------------------------------------------------------------
    // Handler wiring
    // ------------------------------------------------------------------

    /**
     * The transports attach and detach the outbound sender and the prompting
     * activity as connections and screens come and go, so both must accept
     * null without disturbing request handling.
     */
    @Test
    fun theSenderAndActivityCanBeAttachedAndCleared() {
        handler.setMessageSender(NoOpMessageSender())
        assertTrue(call("ping").isSuccess())

        handler.setMessageSender(null)
        assertTrue(call("ping").isSuccess())

        handler.setActivity(null)
        assertTrue(call("ping").isSuccess())
    }

    @Test
    fun theConnectedPeerIdentityRoundTripsAndIsClearedOnDisconnect() {
        val peer = "cd".repeat(32)
        handler.setConnectedDevicePublicKeyHex(peer)
        assertEquals(peer, handler.getConnectedDevicePublicKeyHex())

        handler.setSessionId("aa:bb:cc:dd:ee:ff")
        assertEquals(
            "an active session must not clear the peer identity",
            peer,
            handler.getConnectedDevicePublicKeyHex()
        )

        // A null session id means "disconnected", which drops the peer.
        handler.setSessionId(null)
        assertNull(handler.getConnectedDevicePublicKeyHex())
    }

    // ------------------------------------------------------------------
    // local.getCapabilities: the ECDH API floor
    // ------------------------------------------------------------------

    /**
     * Keystore key agreement needs `PURPOSE_AGREE_KEY`, which exists only from
     * API 31, so the capability must match the device under test; below 31
     * local.ecdh refuses plainly instead of failing inside the Keystore.
     */
    @Test
    fun getCapabilitiesAdvertisesEcdhOnlyFromApi31() {
        val sdk = Build.VERSION.SDK_INT
        val result = call("local.getCapabilities").ok()
        assertEquals("supportsECDH on API $sdk", sdk >= 31, result.getBoolean("supportsECDH"))

        if (sdk < 31) {
            val response = call(
                "local.ecdh",
                JSONObject().put("keyId", "ecdh-floor-$runId").put("peerPublicKey", b64(ByteArray(91)))
            )
            assertEquals(ErrorCodes.ECDH_FAILED, response.errorCode())
            val message = response.error?.message.orEmpty()
            assertTrue(message, message.contains("requires Android 12 (API 31)"))
        }
    }

    /**
     * The capability contract: a client may pick any advertised algorithm, so
     * local.generateKey must create it and an asymmetric one must sign.
     */
    @Test
    fun everyAdvertisedAlgorithmCanBeGeneratedAndUsed() {
        val algorithms = call("local.getCapabilities").ok().getJSONArray("algorithms")
        assertTrue("capabilities list at least one algorithm", algorithms.length() > 0)
        for (i in 0 until algorithms.length()) {
            val algorithm = algorithms.getString(i)
            val keyType = when {
                algorithm.startsWith("AES") -> KeyTypes.SECRET
                algorithm.startsWith("HMAC") -> KeyTypes.HMAC
                else -> KeyTypes.SIGNING
            }
            val keyId = generateKey("advertised-${algorithm.lowercase()}-$runId", keyType, algorithm)
            if (keyType == KeyTypes.SIGNING) {
                val response = call(
                    "local.sign",
                    JSONObject().put("keyId", keyId).put("data", b64("advertised".toByteArray()))
                        .put("algorithm", algorithm)
                )
                assertTrue("$algorithm must sign: " + response.toJsonString(), response.isSuccess())
            }
        }
    }

    // ------------------------------------------------------------------
    // local.listKeys filters
    // ------------------------------------------------------------------

    /**
     * The desktop filters by key type (`xkey device keys --type signing`), and
     * the filtered query is a different DAO call from the unfiltered listing.
     */
    @Test
    fun listKeysFiltersByKeyType() {
        val ecKey = generateKey("filter-ec-$runId", KeyTypes.SIGNING, "ES256")
        val aesKey = generateKey("filter-aes-$runId", KeyTypes.SECRET, "AES256")

        val listed = keyIdsOf(call("local.listKeys", JSONObject().put("keyType", KeyTypes.SIGNING)))

        assertTrue("the signing key must be listed", listed.contains(ecKey))
        assertFalse("a secret key must not appear under keyType=signing", listed.contains(aesKey))
    }

    /** Every key minted through the protocol is tagged `remote_ble`. */
    @Test
    fun listKeysFiltersBySource() {
        val keyId = generateKey("filter-source-$runId", KeyTypes.SIGNING, "ES256")

        val matching = keyIdsOf(call("local.listKeys", JSONObject().put("source", "remote_ble")))
        assertTrue(matching.contains(keyId))

        val other = keyIdsOf(call("local.listKeys", JSONObject().put("source", filterSource)))
        assertFalse("a different source must not match", other.contains(keyId))
    }

    /** Both filters together intersect rather than pick one. */
    @Test
    fun listKeysAppliesTheKeyTypeAndSourceFiltersTogether() {
        val keyId = generateKey("filter-both-$runId", KeyTypes.SIGNING, "ES256")

        val both = keyIdsOf(
            call(
                "local.listKeys",
                JSONObject().put("keyType", KeyTypes.SIGNING).put("source", "remote_ble")
            )
        )
        assertTrue(both.contains(keyId))

        val mismatched = keyIdsOf(
            call(
                "local.listKeys",
                JSONObject().put("keyType", KeyTypes.SIGNING).put("source", filterSource)
            )
        )
        assertFalse(
            "the source filter must still apply when a key type is given",
            mismatched.contains(keyId)
        )
    }

    @Test
    fun listKeysReportsACountThatMatchesTheEntriesItReturned() {
        generateKey("filter-count-$runId", KeyTypes.SIGNING, "ES256")

        val result = call("local.listKeys", JSONObject().put("keyType", KeyTypes.SIGNING)).ok()

        assertEquals(result.getJSONArray("keys").length(), result.getInt("count"))
    }

    // ------------------------------------------------------------------
    // local.deleteKey
    // ------------------------------------------------------------------

    /**
     * go-xkms sends `keyId`; the legacy base-protocol shape used
     * `credentialId`. Both must address the same key, or a desktop on either
     * vintage silently fails to delete anything.
     */
    @Test
    fun deleteKeyAcceptsTheLegacyCredentialIdSpelling() {
        val keyId = generateKey("delete-alias-$runId", KeyTypes.SIGNING, "ES256")

        val response = call("local.deleteKey", JSONObject().put("credentialId", keyId))

        assertTrue(response.ok().getBoolean("deleted"))
        assertNull(
            "the key row must be gone",
            runBlocking { XKeyDatabase.getInstance(context).keyDao().getByKeyId(keyId) }
        )
    }

    @Test
    fun deleteKeyWithNeitherIdentifierIsInvalidParams() {
        val response = call("local.deleteKey", JSONObject().put("label", "nothing addressable"))

        assertEquals(ErrorCodes.INVALID_PARAMS, response.errorCode())
    }

    @Test
    fun deleteKeyPrefersKeyIdWhenBothSpellingsArePresent() {
        val target = generateKey("delete-both-$runId", KeyTypes.SIGNING, "ES256")
        val bystander = generateKey("delete-bystander-$runId", KeyTypes.SIGNING, "ES256")

        call(
            "local.deleteKey",
            JSONObject().put("keyId", target).put("credentialId", bystander)
        )

        runBlocking {
            val dao = XKeyDatabase.getInstance(context).keyDao()
            assertNull("keyId names the key to delete", dao.getByKeyId(target))
            assertNotNull("credentialId must be ignored when keyId is present", dao.getByKeyId(bystander))
        }
    }

    // ------------------------------------------------------------------
    // local.setKeyPolicy
    // ------------------------------------------------------------------

    /**
     * Sharing is granted after the fact from the desktop. The flag has to reach
     * the row, otherwise `local.importSharedKey` keeps refusing.
     */
    @Test
    fun setKeyPolicyTogglesShareableOnTheStoredKey() {
        val keyId = generateKey("policy-$runId", KeyTypes.SECRET, "AES256")
        assertFalse(storedKey(keyId).shareable)

        assertTrue(
            call("local.setKeyPolicy", JSONObject().put("keyId", keyId).put("shareable", true))
                .ok().getBoolean("updated")
        )
        assertTrue(storedKey(keyId).shareable)

        call("local.setKeyPolicy", JSONObject().put("keyId", keyId).put("shareable", false))
        assertFalse(storedKey(keyId).shareable)
    }

    /** A request that names no flag is accepted but changes nothing. */
    @Test
    fun setKeyPolicyWithoutAFlagLeavesTheKeyUntouched() {
        val keyId = generateKey("policy-noop-$runId", KeyTypes.SECRET, "AES256")
        val before = storedKey(keyId).shareable

        assertTrue(
            call("local.setKeyPolicy", JSONObject().put("keyId", keyId)).ok().getBoolean("updated")
        )

        assertEquals(before, storedKey(keyId).shareable)
    }

    @Test
    fun setKeyPolicyRequiresParameters() {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("local.setKeyPolicy").errorCode())
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.setKeyPolicy", JSONObject().put("shareable", true)).errorCode()
        )
    }

    // ------------------------------------------------------------------
    // local.decrypt (RSA-OAEP)
    // ------------------------------------------------------------------

    /**
     * The desktop encrypts to the phone's RSA public key and asks the phone to
     * decrypt; nothing else in the suite mints an RSA key, so this is the only
     * exercise of the `local.decrypt` handler.
     *
     * AndroidKeyStore has historically defaulted the OAEP MGF1 digest
     * differently from the JCA providers, and the handler decrypts without
     * explicit parameters. Both parameterisations are offered and one must
     * round-trip — which one is the interop answer for this platform.
     */
    @Test
    fun decryptRecoversRsaOaepCiphertextProducedOffDevice() {
        val keyId = generateKey("rsa-$runId", KeyTypes.ENCRYPTION, "RS256")
        val publicKeyDer = Base64.getDecoder().decode(
            call("local.getPublicKey", JSONObject().put("keyId", keyId).put("format", ExportFormats.DER))
                .ok().getString("publicKey")
        )
        val publicKey = KeyFactory.getInstance("RSA")
            .generatePublic(X509EncodedKeySpec(publicKeyDer))

        val plaintext = "rsa oaep payload for the phone".toByteArray()
        val parameterisations = listOf(
            OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT
            ),
            OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
            )
        )

        var recovered: ByteArray? = null
        for (spec in parameterisations) {
            val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, spec)
            val response = call(
                "local.decrypt",
                JSONObject().put("keyId", keyId).put("ciphertext", b64(cipher.doFinal(plaintext)))
            )
            if (response.isSuccess()) {
                recovered = Base64.getDecoder().decode(response.ok().getString("plaintext"))
                break
            }
        }

        assertNotNull("the phone must decrypt RSA-OAEP ciphertext from a peer", recovered)
        assertArrayEquals(plaintext, recovered!!)
    }

    @Test
    fun decryptRequiresBothOfItsParameters() {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("local.decrypt").errorCode())
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.decrypt", JSONObject().put("keyId", "anything")).errorCode()
        )
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.decrypt", JSONObject().put("ciphertext", b64(ByteArray(4)))).errorCode()
        )
    }

    // ------------------------------------------------------------------
    // local.hmac on software-backed material
    // ------------------------------------------------------------------

    /**
     * An exportable key never enters the Keystore: its raw material lives in
     * [SoftwareKeyStore] and the MAC is computed over that material directly.
     * The result must still match a plain JCA MAC, or a desktop that verifies
     * the tag itself would reject every code the phone produces.
     */
    @Test
    fun hmacUsesTheSoftwareMaterialForAnExportableKey() {
        val keyId = "hmac-sw-$runId"
        createdKeyIds.add(keyId)
        assertTrue(
            call(
                "local.generateKey",
                JSONObject()
                    .put("keyId", keyId)
                    .put("keyType", KeyTypes.HMAC)
                    .put("algorithm", "HMAC-SHA256")
                    .put("exportable", true)
                    .put("shareable", true)
                    .put("requireUserVerification", false)
                    .put("preferStrongBox", false)
            ).isSuccess()
        )

        val data = "software hmac payload".toByteArray()
        val mac = Base64.getDecoder().decode(
            call("local.hmac", JSONObject().put("keyId", keyId).put("data", b64(data)))
                .ok().getString("mac")
        )

        val material = softwareKeys.get(keyId)
        assertNotNull("an exportable key must be stored in software", material)
        val expected = javax.crypto.Mac.getInstance("HmacSHA256").apply {
            init(javax.crypto.spec.SecretKeySpec(material!!.material, "HmacSHA256"))
        }.doFinal(data)

        assertArrayEquals("the software MAC must match a plain JCA MAC", expected, mac)
    }

    /** A 512-bit software HMAC key gets 64 bytes of material, not the 256-bit default. */
    @Test
    fun anExportableSha512HmacKeyCarries512BitsOfMaterial() {
        val keyId = "hmac-sw-512-$runId"
        createdKeyIds.add(keyId)
        val result = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", KeyTypes.HMAC)
                .put("algorithm", "HMAC-SHA512")
                .put("exportable", true)
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        ).ok()

        assertEquals(512, result.getInt("keySizeBits"))
        assertEquals(64, softwareKeys.get(keyId)!!.material.size)
    }

    // ------------------------------------------------------------------
    // local.generateKey shapes
    // ------------------------------------------------------------------

    /**
     * A FIDO2 key is the only kind that also carries a COSE public key: a
     * relying party consumes COSE, while everything else on the wire is DER.
     */
    @Test
    fun aFido2KeyAlsoReturnsACosePublicKey() {
        val keyId = "fido2-$runId"
        createdKeyIds.add(keyId)
        val result = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", KeyTypes.FIDO2)
                .put("algorithm", "ES256")
                .put("rpId", "keyfamily.example.com")
                .put("rpName", "Key Family Test RP")
                .put("userName", "user@example.com")
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        ).ok()

        assertTrue("a FIDO2 key must publish a COSE key", result.has("publicKeyCose"))
        assertTrue(Base64.getDecoder().decode(result.getString("publicKeyCose")).isNotEmpty())

        val stored = storedKey(keyId)
        assertEquals("keyfamily.example.com", stored.rpId)
        assertNotNull("the COSE encoding must be persisted too", stored.publicKeyCose)
    }

    /** A non-FIDO2 key of the same algorithm carries no COSE encoding. */
    @Test
    fun aSigningKeyOfTheSameAlgorithmCarriesNoCoseEncoding() {
        val keyId = "signing-nocose-$runId"
        createdKeyIds.add(keyId)
        val result = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", KeyTypes.SIGNING)
                .put("algorithm", "ES256")
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        ).ok()

        assertFalse(result.has("publicKeyCose"))
        assertNull(storedKey(keyId).publicKeyCose)
    }

    /**
     * `shareable` and `sharingPolicy` have to agree: a key stored shareable but
     * left on the PRIVATE default is refused by the sharing gate despite the
     * caller having asked for it.
     */
    @Test
    fun aShareableHardwareKeyIsStoredWithAMatchingSharingPolicy() {
        val keyId = "shareable-hw-$runId"
        createdKeyIds.add(keyId)
        call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", KeyTypes.SECRET)
                .put("algorithm", "AES256")
                .put("shareable", true)
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )

        val stored = storedKey(keyId)
        assertTrue(stored.shareable)
        assertEquals(SharingPolicyType.ALL_PEERS, stored.sharingPolicy)
    }

    @Test
    fun aKeyThatIsNotShareableStaysPrivate() {
        val keyId = generateKey("private-hw-$runId", KeyTypes.SECRET, "AES256")

        val stored = storedKey(keyId)
        assertFalse(stored.shareable)
        assertEquals(SharingPolicyType.PRIVATE, stored.sharingPolicy)
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private fun call(method: String): Response = dispatch(method, null)

    private fun call(method: String, params: JSONObject): Response = dispatch(method, params)

    /**
     * Written without default arguments on purpose: a function that carries a
     * default argument and also builds a coroutine lambda has repeatedly
     * crashed the Kotlin JVM backend in these suites
     * (BackendException at RecordEnclosingMethodsLowering).
     */
    private fun dispatch(method: String, params: JSONObject?): Response {
        val request = Request(nextRequestId.getAndIncrement(), method, params)
        return runBlocking { handler.handleRequest(request) }
    }

    private fun generateKey(keyId: String, keyType: String, algorithm: String): String {
        createdKeyIds.add(keyId)
        val response = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", keyType)
                .put("algorithm", algorithm)
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        assertTrue(
            "key generation must succeed: " + response.toJsonString(),
            response.isSuccess()
        )
        return keyId
    }

    private fun storedKey(keyId: String) =
        runBlocking { XKeyDatabase.getInstance(context).keyDao().getByKeyId(keyId) }
            ?: throw AssertionError("expected a stored key row for $keyId")

    private fun keyIdsOf(response: Response): Set<String> {
        val keys = response.ok().getJSONArray("keys")
        return (0 until keys.length()).map { keys.getJSONObject(it).getString("keyId") }.toSet()
    }

    /**
     * Returns the result of a successful response.
     *
     * [Response.result] is a nullable property of another module, so Kotlin
     * cannot smart-cast it here; every reader goes through this accessor.
     */
    private fun Response.ok(): JSONObject =
        result ?: throw AssertionError("expected a successful response, got: " + toJsonString())

    private fun Response.errorCode(): Int =
        error?.code ?: throw AssertionError("expected an error response, got: " + toJsonString())

    private fun b64(data: ByteArray): String = Base64.getEncoder().encodeToString(data)
}

/** A sender that accepts and discards, so attaching one is observable but inert. */
private class NoOpMessageSender : MessageSender {
    override suspend fun sendMessage(message: ByteArray) = Unit
}
