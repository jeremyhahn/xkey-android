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

package com.automatethethings.xkey.e2e

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.pin.PinManager
import com.automatethethings.xkey.piv.PivKeyManager
import com.automatethethings.xkey.protocol.AttestTranscript
import com.automatethethings.xkey.protocol.AttestedKeyFingerprint
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.PinSettingsRepository
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.tcp.TcpHsmServer
import com.automatethethings.xkey.tcp.TcpHsmState
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import javax.crypto.KeyAgreement

/**
 * Wire-level integration suite: starts the app's real TCP pairing stack
 * ([TcpHsmServer] -> StreamPairingSession -> [RequestHandler]) in-process and
 * drives it from [ProtocolTestClient], a faithful reimplementation of the
 * go-xkms desktop initiator (identity exchange + Noise XX + encrypted
 * JSON-RPC). Every supported protocol family is exercised end-to-end through
 * the exact bytes a paired desktop would send.
 */
@RunWith(AndroidJUnit4::class)
class ProtocolIntegrationTest {

    companion object {
        private const val TEST_PORT = 18444

        private lateinit var context: Context
        private lateinit var server: TcpHsmServer
        private lateinit var client: ProtocolTestClient
        private lateinit var pairedDeviceRepository: PairedDeviceRepository

        /** Unique per-run suffix so persistent stores don't collide across runs. */
        private val runId = System.currentTimeMillis().toString(36)

        private fun b64(data: ByteArray): String = Base64.getEncoder().encodeToString(data)
        private fun unb64(data: String): ByteArray = Base64.getDecoder().decode(data)

        @JvmStatic
        @BeforeClass
        fun startServerAndConnect() {
            context = ApplicationProvider.getApplicationContext()

            // PIN tests need a clean slate; PIN state persists in DataStore.
            runBlocking { PinSettingsRepository(context).clearSettings() }

            pairedDeviceRepository = PairedDeviceRepository(context)
            val handler = RequestHandler(
                context = context,
                keystoreManager = KeystoreManager(context),
                biometricLauncher = null,
                sessionAuthManager = SessionAuthManager(),
                pairedDeviceRepository = pairedDeviceRepository,
                pinManager = PinManager(PinSettingsRepository(context)),
                pivKeyManager = PivKeyManager(XKeyDatabase.getInstance(context).pivSlotDao())
            )
            // No UI is attached: disable biometric gating like a headless HSM.
            handler.updateSettings(
                BiometricSettingsData(
                    uvPolicy = UserVerificationPolicy.DISABLED,
                    attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
                )
            )

            server = TcpHsmServer(
                requestHandler = handler,
                messageRouter = BidirectionalMessageRouter(handler),
                pairingCallback = object : com.automatethethings.xkey.ble.PairingConfirmationCallback {
                    override suspend fun onPairingConfirmationRequired(
                        deviceName: String,
                        publicKeyFingerprint: String
                    ): Boolean = true
                },
                pairedDeviceRepository = pairedDeviceRepository
            )
            server.start(context, TEST_PORT)
            runBlocking {
                withTimeout(5000) { server.state.first { it is TcpHsmState.Listening } }
            }

            client = ProtocolTestClient(TEST_PORT)
            client.connect()
            val pairing = client.confirmPairing()
            assertTrue(pairing.optBoolean("confirmed"))
        }

        @JvmStatic
        @AfterClass
        fun tearDown() {
            if (::client.isInitialized) client.close()
            if (::server.isInitialized) server.stop()
            cleanUpPersistentState()
        }

        /**
         * Removes everything this suite persisted. Without it the leftover keys
         * and PIV slot leak into other suites, whose hero cards assert an empty
         * store.
         */
        private fun cleanUpPersistentState() = runBlocking {
            val db = XKeyDatabase.getInstance(context)
            val softwareKeyStore = com.automatethethings.xkey.crypto.SoftwareKeyStore(context)
            db.keyDao().getAll()
                .filter { it.keyId.contains(runId) || it.keyId.startsWith("itest-") }
                .forEach {
                    softwareKeyStore.delete(it.keyId)
                    db.keyDao().deleteByKeyId(it.keyId)
                }
            softwareKeyStore.delete("itest-shared-sym-$runId")

            PivKeyManager(db.pivSlotDao()).deleteKey(
                com.automatethethings.xkey.piv.PivSlot.AUTHENTICATION
            )

            db.contactDao().getAll()
                .filter { it.source == "shared" && it.name == "Desktop Shared Key" }
                .forEach { db.contactDao().deleteById(it.id) }

            PinSettingsRepository(context).clearSettings()
        }
    }

    // ------------------------------------------------------------------
    // Base methods
    // ------------------------------------------------------------------

    @Test
    fun basePingGetInfoCapabilities() {
        client.call("ping")
        val info = client.call("getInfo")
        assertTrue(info.length() > 0)
        val caps = client.call("local.getCapabilities")
        assertTrue(caps.length() > 0)
    }

    // ------------------------------------------------------------------
    // Asymmetric key lifecycle
    // ------------------------------------------------------------------

    @Test
    fun keyLifecycleGenerateSignVerifyDelete() {
        val keyId = "itest-ec-$runId"
        val generated = client.call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "signing")
                .put("algorithm", "ES256")
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        val publicKeyDer = unb64(generated.getString("publicKeyDer"))

        val data = "integration-test-payload".toByteArray()
        val signed = client.call(
            "local.sign",
            JSONObject().put("keyId", keyId).put("data", b64(data))
        )
        val signature = unb64(signed.getString("signature"))

        // Verify the signature off-device against the returned SPKI.
        val publicKey = java.security.KeyFactory.getInstance("EC")
            .generatePublic(java.security.spec.X509EncodedKeySpec(publicKeyDer))
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(data)
        assertTrue("phone signature must verify", verifier.verify(signature))

        val exported = client.call(
            "local.getPublicKey",
            JSONObject().put("keyId", keyId).put("format", "der")
        )
        assertTrue(exported.length() > 0)

        val listed = client.call("local.listKeys")
        val keys = listed.getJSONArray("keys")
        assertTrue((0 until keys.length()).any {
            keys.getJSONObject(it).optString("keyId") == keyId
        })

        val info = client.call("local.getKeyInfo", JSONObject().put("keyId", keyId))
        assertTrue(info.length() > 0)

        client.call("local.deleteKey", JSONObject().put("keyId", keyId))
        val err = client.callExpectingError("local.sign",
            JSONObject().put("keyId", keyId).put("data", b64(data)))
        assertNotNull("signing with a deleted key must fail", err)
        assertEquals(ErrorCodes.KEY_NOT_FOUND, err!!.code)
    }

    // ------------------------------------------------------------------
    // Symmetric crypto: hardware AES, software (exportable) AES, HMAC
    // ------------------------------------------------------------------

    @Test
    fun hardwareAesEncryptDecryptRoundtrip() {
        val keyId = "itest-aes-hw-$runId"
        client.call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "secret")
                .put("algorithm", "AES256")
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        val plaintext = "hardware aes roundtrip".toByteArray()
        val encrypted = client.call(
            "local.symmetricEncrypt",
            JSONObject().put("keyId", keyId).put("data", b64(plaintext))
        )
        val decrypted = client.call(
            "local.symmetricDecrypt",
            JSONObject().put("keyId", keyId).put("data", encrypted.getString("data"))
        )
        assertArrayEquals(plaintext, unb64(decrypted.getString("data")))
        client.call("local.deleteKey", JSONObject().put("keyId", keyId))
    }

    @Test
    fun softwareExportableAesRoundtrip() {
        val keyId = "itest-aes-sw-$runId"
        client.call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "secret")
                .put("algorithm", "AES256")
                .put("exportable", true)
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        val plaintext = "software aes roundtrip".toByteArray()
        val encrypted = client.call(
            "local.symmetricEncrypt",
            JSONObject().put("keyId", keyId).put("data", b64(plaintext))
        )
        val decrypted = client.call(
            "local.symmetricDecrypt",
            JSONObject().put("keyId", keyId).put("data", encrypted.getString("data"))
        )
        assertArrayEquals(plaintext, unb64(decrypted.getString("data")))
    }

    @Test
    fun exportableAsymmetricKeyIsRefused() {
        val err = client.callExpectingError(
            "local.generateKey",
            JSONObject()
                .put("keyId", "itest-refuse-$runId")
                .put("keyType", "signing")
                .put("algorithm", "ES256")
                .put("exportable", true)
                .put("requireUserVerification", false)
        )
        assertNotNull("exportable asymmetric keys must be refused", err)
    }

    @Test
    fun hmacComputes() {
        val keyId = "itest-hmac-$runId"
        client.call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "hmac")
                .put("algorithm", "HMAC-SHA256")
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        val mac = client.call(
            "local.hmac",
            JSONObject().put("keyId", keyId).put("data", b64("hmac me".toByteArray()))
        )
        assertEquals(32, unb64(mac.getString("mac")).size)
        client.call("local.deleteKey", JSONObject().put("keyId", keyId))
    }

    // ------------------------------------------------------------------
    // ECDH
    // ------------------------------------------------------------------

    @Test
    fun ecdhSharedSecretMatchesPeerComputation() {
        val keyId = "itest-ecdh-$runId"
        val generated = client.call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "signing")
                .put("algorithm", "ES256")
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        val phonePublic = java.security.KeyFactory.getInstance("EC")
            .generatePublic(java.security.spec.X509EncodedKeySpec(unb64(generated.getString("publicKeyDer"))))

        // Peer (desktop-side) ephemeral keypair.
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val peer = kpg.generateKeyPair()

        val result = client.call(
            "local.ecdh",
            JSONObject().put("keyId", keyId).put("peerPublicKey", b64(peer.public.encoded))
        )
        val phoneSecret = unb64(result.getString("sharedSecret"))

        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(peer.private)
        agreement.doPhase(phonePublic, true)
        assertArrayEquals("ECDH secrets must agree", agreement.generateSecret(), phoneSecret)
        client.call("local.deleteKey", JSONObject().put("keyId", keyId))
    }

    // ------------------------------------------------------------------
    // PIN family
    // ------------------------------------------------------------------

    @Test
    fun pinLifecycle() {
        val soPin = "87654321"
        val userPin = "123456"
        val newUserPin = "654321"

        val statusBefore = client.call("local.pinStatus")
        if (!statusBefore.getBoolean("soPinSet")) {
            client.call(
                "local.pinSet",
                JSONObject().put("pinType", "SO_PIN").put("newPin", soPin)
            )
        }
        client.call(
            "local.pinSet",
            JSONObject().put("pinType", "USER_PIN").put("soPin", soPin).put("newPin", userPin)
        )

        assertTrue(
            client.call("local.pinVerify", JSONObject().put("pin", userPin).put("pinType", "USER_PIN"))
                .getBoolean("verified")
        )
        assertTrue(
            client.call("local.pinVerify", JSONObject().put("pin", soPin).put("pinType", "SO_PIN"))
                .getBoolean("verified")
        )

        client.call(
            "local.pinChange",
            JSONObject().put("pinType", "USER_PIN").put("currentPin", userPin).put("newPin", newUserPin)
        )
        assertTrue(
            client.call("local.pinVerify", JSONObject().put("pin", newUserPin).put("pinType", "USER_PIN"))
                .getBoolean("verified")
        )

        val wrong = client.callExpectingError(
            "local.pinVerify",
            JSONObject().put("pin", "000000").put("pinType", "USER_PIN")
        )
        assertNotNull("wrong PIN must be rejected", wrong)

        client.call("local.pinResetLockout", JSONObject().put("soPin", soPin))

        val status = client.call("local.pinStatus")
        assertTrue(status.getBoolean("soPinSet"))
        assertTrue(status.getBoolean("userPinSet"))
        assertFalse(status.getBoolean("userLocked"))
    }

    // ------------------------------------------------------------------
    // PIV family
    // ------------------------------------------------------------------

    @Test
    fun pivLifecycle() {
        val slotId = "9a"
        val generated = client.call(
            "local.pivGenerateKey",
            JSONObject().put("slotId", slotId).put("algorithm", "ES256")
        )
        assertTrue(generated.getBoolean("hasKey"))
        val publicKeyDer = unb64(generated.getString("publicKey"))

        val slots = client.call("local.pivListSlots").getJSONArray("slots")
        val slot9a = (0 until slots.length())
            .map { slots.getJSONObject(it) }
            .first { it.getString("slotId").equals(slotId, ignoreCase = true) }
        assertTrue(slot9a.getBoolean("hasKey"))

        val data = "piv sign payload".toByteArray()
        val signed = client.call(
            "local.pivSign",
            JSONObject().put("slotId", slotId).put("data", b64(data)).put("algorithm", "ES256")
        )
        val publicKey = java.security.KeyFactory.getInstance("EC")
            .generatePublic(java.security.spec.X509EncodedKeySpec(publicKeyDer))
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(data)
        assertTrue("PIV signature must verify", verifier.verify(unb64(signed.getString("signature"))))

        // Import the slot key's own certificate (#173: a certificate must be
        // for the slot's key) and read it back.
        val certDer = slotCertificateDer(slotId)
        client.call(
            "local.pivImportCert",
            JSONObject().put("slotId", slotId).put("certificate", b64(certDer))
        )
        val fetched = client.call("local.pivGetCert", JSONObject().put("slotId", slotId))
        assertArrayEquals(certDer, unb64(fetched.getString("certificate")))
    }

    /**
     * A certificate for another key is refused with INVALID_PARAMS and the
     * slot keeps the certificate it had (#173).
     */
    @Test
    fun pivImportRefusesACertificateForAnotherKey() {
        val slotId = "9a"
        client.call(
            "local.pivGenerateKey",
            JSONObject().put("slotId", slotId).put("algorithm", "ES256")
        )
        val before = unb64(
            client.call("local.pivGetCert", JSONObject().put("slotId", slotId)).getString("certificate")
        )

        val err = client.callExpectingError(
            "local.pivImportCert",
            JSONObject().put("slotId", slotId)
                .put("certificate", b64(generateSelfSignedCertDer("itest-piv-other-$runId")))
        )

        assertNotNull("a certificate for another key must be refused", err)
        assertEquals(ErrorCodes.INVALID_PARAMS, err!!.code)
        val after = client.call("local.pivGetCert", JSONObject().put("slotId", slotId))
        assertArrayEquals(before, unb64(after.getString("certificate")))
    }

    /** The self-signed certificate the Keystore holds for PIV slot [slotId]'s key. */
    private fun slotCertificateDer(slotId: String): ByteArray {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return ks.getCertificate("xkey_piv_${slotId.uppercase()}").encoded
    }

    /** Generates an AndroidKeyStore keypair and returns its self-signed cert DER. */
    private fun generateSelfSignedCertDer(alias: String): ByteArray {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        kpg.initialize(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
        )
        kpg.generateKeyPair()
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val der = ks.getCertificate(alias).encoded
        ks.deleteEntry(alias)
        return der
    }

    /**
     * PIV results must carry go-xkms's field names as well as the legacy
     * Android ones. go-xkms reads `slot`, `has_key`, `has_certificate`,
     * `public_key_der` and `certificate_der`; before this, its PIV commands
     * decoded an all-zero slot list and empty certificates.
     */
    @Test
    fun pivResultsCarryTheGoFieldNames() {
        val slotId = "9a"
        val generated = client.call(
            "local.pivGenerateKey",
            JSONObject().put("slot", slotId).put("algorithm", "ECDSA-P256")
        )
        assertTrue("generate must emit slot", generated.has("slot"))
        assertTrue("generate must emit public_key_der", generated.has("public_key_der"))
        assertTrue("generate must emit has_key", generated.getBoolean("has_key"))

        val slots = client.call("local.pivListSlots").getJSONArray("slots")
        val entry = (0 until slots.length())
            .map { slots.getJSONObject(it) }
            .first { it.optString("slot").equals(slotId, ignoreCase = true) }
        assertTrue("listSlots must emit has_key", entry.has("has_key"))
        assertTrue("listSlots must emit has_certificate", entry.has("has_certificate"))
        assertTrue("listSlots must emit public_key_der", entry.has("public_key_der"))

        val certDer = slotCertificateDer(slotId)
        client.call(
            "local.pivImportCert",
            JSONObject().put("slot", slotId).put("certificate_der", b64(certDer))
        )
        val fetched = client.call("local.pivGetCert", JSONObject().put("slot", slotId))
        assertArrayEquals(
            "getCert must emit certificate_der",
            certDer,
            unb64(fetched.getString("certificate_der"))
        )
    }

    // ------------------------------------------------------------------
    // OATH family
    // ------------------------------------------------------------------

    @Test
    fun oathLifecycle() {
        val name = "itest-oath-$runId"
        val added = client.call(
            "local.oathAdd",
            JSONObject().put(
                "credential",
                JSONObject()
                    .put("name", name)
                    .put("issuer", "IntegrationTest")
                    .put("account_name", "user@example.com")
                    .put("secret", "JBSWY3DPEHPK3PXP")
                    .put("type", "totp")
                    .put("algorithm", "SHA1")
                    .put("digits", 6)
                    .put("period", 30)
            )
        )
        assertTrue(added.getBoolean("success"))

        val listed = client.call("local.oathList").getJSONArray("credentials")
        val entry = (0 until listed.length())
            .map { listed.getJSONObject(it) }
            .firstOrNull { it.optString("account_name") == "user@example.com" && it.optString("issuer") == "IntegrationTest" }
        assertNotNull("added credential must appear in list", entry)
        // Secrets must never leak in listings.
        assertEquals("", entry!!.optString("secret"))

        val credentialId = entry.getString("name")
        val code = client.call(
            "local.oathGenerate",
            JSONObject().put("credential_id", credentialId)
        )
        assertEquals(6, code.getString("code").length)
        assertTrue(code.getInt("expires_in") in 1..30)

        assertTrue(
            client.call("local.oathRemove", JSONObject().put("credential_id", credentialId))
                .getBoolean("deleted")
        )
    }

    // ------------------------------------------------------------------
    // Sync family
    // ------------------------------------------------------------------

    @Test
    fun syncStatusAndStores() {
        val status = client.call("local.syncStatus")
        assertTrue(status.getString("device_id").isNotEmpty())
        assertNotNull(status.getJSONObject("store_checksums"))

        val trust = client.call("local.syncTrustStore", JSONObject().put("certificates", JSONArray()))
        assertEquals(0, trust.getInt("added"))
        assertNotNull(trust.getJSONArray("remote"))

        val oath = client.call("local.syncOATH", JSONObject().put("credentials", JSONArray()))
        assertNotNull(oath.getJSONArray("remote"))

        val passwords = client.call("local.syncPasswords", JSONObject().put("passwords", JSONArray()))
        assertNotNull(passwords.getJSONArray("remote"))
    }

    // ------------------------------------------------------------------
    // Backup family
    // ------------------------------------------------------------------

    @Test
    fun backupRoundtrip() {
        val blob = ByteArray(256).also { SecureRandom().nextBytes(it) }
        val created = client.call(
            "local.createBackup",
            JSONObject().put("backup_data", b64(blob)).put("label", "itest")
        )
        assertTrue(created.getBoolean("success"))
        val backupId = created.getString("backup_id")

        val restored = client.call("local.restoreBackup", JSONObject().put("backup_id", backupId))
        assertArrayEquals(blob, unb64(restored.getString("backup_data")))

        val missing = client.callExpectingError(
            "local.restoreBackup",
            JSONObject().put("backup_id", "does-not-exist")
        )
        assertNotNull(missing)
    }

    // ------------------------------------------------------------------
    // Key sharing family
    // ------------------------------------------------------------------

    @Test
    fun sharePublicKeyFromDesktop() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val pair = kpg.generateKeyPair()
        val pem = "-----BEGIN PUBLIC KEY-----\n" +
            Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(pair.public.encoded) +
            "\n-----END PUBLIC KEY-----\n"

        val result = client.call(
            "local.sharePublicKey",
            JSONObject()
                .put("public_key_pem", pem)
                .put("key_id", "desktop-key-$runId")
                .put("label", "Desktop Shared Key")
                .put("algorithm", "ES256")
        )
        assertTrue(result.getBoolean("accepted"))
    }

    @Test
    fun shareSymmetricStoresKeyButDoesNotMakeItReExportable() {
        val material = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val label = "itest-shared-sym-$runId"
        val shared = client.call(
            "local.shareSymmetric",
            JSONObject()
                .put("wrapped_key", b64(material))
                .put("label", label)
                .put("algorithm", "AES")
                .put("key_size", 256)
        )
        assertTrue(shared.getBoolean("accepted"))

        // A key pushed to us by a peer is accepted for local use, but the peer
        // does not thereby gain the right to pull it back out: inbound shared
        // material is stored non-exportable and non-shareable until the user
        // grants a sharing policy.
        val error = client.callExpectingError(
            "local.importSharedKey",
            JSONObject().put("key_id", label)
        )
        assertNotNull("re-export of an inbound shared key must be refused", error)
        assertEquals(ErrorCodes.OPERATION_DENIED, error!!.code)
    }

    /**
     * A software key created with `shareable` may be exported, proving the
     * policy gate permits the flow the desktop actually uses rather than
     * blocking everything.
     */
    @Test
    fun shareableSoftwareKeyCanBeExported() {
        val keyId = "itest-shareable-sw-$runId"
        client.call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "secret")
                .put("algorithm", "AES256")
                .put("exportable", true)
                .put("shareable", true)
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )

        val exported = client.call("local.importSharedKey", JSONObject().put("key_id", keyId))
        assertTrue("a shareable software key must export its material", exported.getBoolean("exportable"))
        assertEquals(32, unb64(exported.getString("wrapped_key")).size)
    }

    /** A software key created without `shareable` must stay private. */
    @Test
    fun nonShareableSoftwareKeyIsRefused() {
        val keyId = "itest-private-sw-$runId"
        client.call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "secret")
                .put("algorithm", "AES256")
                .put("exportable", true)
                .put("shareable", false)
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )

        val error = client.callExpectingError("local.importSharedKey", JSONObject().put("key_id", keyId))
        assertNotNull("a non-shareable key must not export", error)
        assertEquals(ErrorCodes.OPERATION_DENIED, error!!.code)
    }

    @Test
    fun hardwareKeyExportsPublicOnly() {
        val keyId = "itest-hw-share-$runId"
        // Marked shareable so the policy gate admits the peer; the point of
        // this test is the BACKING boundary — even a fully shareable hardware
        // key must never yield private material.
        client.call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "signing")
                .put("algorithm", "ES256")
                .put("shareable", true)
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        val exported = client.call("local.importSharedKey", JSONObject().put("key_id", keyId))
        assertFalse("hardware keys must never export private material", exported.getBoolean("exportable"))
        assertTrue(exported.getString("public_key_pem").contains("BEGIN PUBLIC KEY"))
        assertFalse(exported.has("wrapped_key"))
        client.call("local.deleteKey", JSONObject().put("keyId", keyId))
    }

    // ------------------------------------------------------------------
    // Attestation
    // ------------------------------------------------------------------

    @Test
    fun attestKeyAndDevice() {
        val keyId = "itest-attest-$runId"
        client.call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "signing")
                .put("algorithm", "ES256")
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        val nonce = b64(ByteArray(32).also { SecureRandom().nextBytes(it) })

        // Policy default: key attestation requires a current desktop device
        // attestation. A freshly paired desktop must be rejected first.
        val gated = client.callExpectingError(
            "local.attestKey",
            JSONObject().put("keyId", keyId).put("nonce", nonce)
        )
        assertNotNull("attestKey must be gated on device attestation by default", gated)

        // The user can waive the requirement per device; then attestation works.
        pairedDeviceRepository.updateDeviceSettings(
            publicKeyHex = client.publicKeyHex,
            requireAttestationForKeyUse = false,
            requireAttestationForKeyAttestation = false,
            attestationGracePeriodMinutes = 60
        )
        val keyAttestation = client.call(
            "local.attestKey",
            JSONObject().put("keyId", keyId).put("nonce", nonce)
        )
        assertTrue(keyAttestation.length() > 0)

        val deviceAttestation = client.call(
            "local.attestDevice",
            JSONObject()
                .put("protocolVersion", AttestTranscript.PROTOCOL_VERSION)
                .put("nonce", nonce)
                .put("purpose", AttestTranscript.PURPOSE_PAIR)
        )
        assertTrue(deviceAttestation.length() > 0)
        client.call("local.deleteKey", JSONObject().put("keyId", keyId))
    }

    /**
     * The real-path prover check for go-xkms#129: a live Noise session, the
     * phone's real `local.attestDevice` handler, and this client verifying the
     * answer exactly as `verifyPairingAttestation` will.
     *
     * The distinguishing property is that **nothing in the transcript comes from
     * the response**. The nonce is the one this client drew, the channel binding
     * is derived from this client's own session, and the fingerprint is derived
     * from the certificate chain rather than read out of a JSON field — which is
     * what makes a passing signature mean the two implementations agree on the
     * bytes rather than merely agreeing to echo each other.
     *
     * Scope, stated precisely so the next reader does not over-read it: this
     * catches a **wrong derivation** on the phone, because `client.channelBinding()`
     * is computed here from this end's own session and the signature has to verify
     * against it.
     *
     * It no longer catches an *echoing* phone, and cannot: the go-xkms#129
     * addendum removed `channelBinding` from the request, so there is no field to
     * echo. An earlier version of this test sent a deliberately wrong binding for
     * exactly that purpose — measured, it was the only reason the echo mutant went
     * red here. That mutant is now unrepresentable rather than uncaught.
     */
    @Test
    fun deviceAttestationSignsALiveTranscriptTheDesktopCanVerify() {
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }

        val result = client.call(
            "local.attestDevice",
            JSONObject()
                .put("protocolVersion", AttestTranscript.PROTOCOL_VERSION)
                .put("nonce", b64(nonce))
                .put("purpose", AttestTranscript.PURPOSE_REATTEST)
        )

        assertEquals(2, result.getInt("protocolVersion"))
        assertEquals("ES256", result.getString("signatureAlgorithm"))
        assertEquals(AttestTranscript.PURPOSE_REATTEST, result.getString("purpose"))

        val chain = result.getJSONArray("certificateChain")
        assertTrue("a device attestation must carry a chain", chain.length() > 0)
        val leaf = CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(Base64.getDecoder().decode(chain.getString(0)))
        ) as X509Certificate

        val transcript = AttestTranscript.build(
            purpose = AttestTranscript.PURPOSE_REATTEST,
            nonce = nonce,
            channelBinding = client.channelBinding(),
            deviceFingerprint = AttestedKeyFingerprint.of(leaf.encoded)
        )
        val verified = Signature.getInstance("SHA256withECDSA").run {
            initVerify(leaf.publicKey)
            update(transcript)
            verify(Base64.getDecoder().decode(result.getString("signature")))
        }
        assertTrue("the phone's signature must verify over the desktop's transcript", verified)
    }

    // ------------------------------------------------------------------
    // FIDO2 listing
    // ------------------------------------------------------------------

    @Test
    fun fido2CredentialsList() {
        val result = client.call(
            "local.listFido2Credentials",
            JSONObject().put("rpId", "integration-test.example.com")
        )
        assertNotNull(result.getJSONArray("credentials"))
    }

    // ------------------------------------------------------------------
    // Protocol error handling
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Request generation echo (#10, go-xkms#128)
    //
    // Checked on the raw response text: this runs on the platform org.json,
    // which reads an integer above Long as a Double, so only the text shows
    // whether a uint64 came back digit for digit.
    // ------------------------------------------------------------------

    @Test
    fun everyMethodFamilyEchoesTheGeneration() {
        val families = listOf(
            "ping", "getInfo", "local.listKeys", "local.pinStatus",
            "local.oathList", "local.pivListSlots", "local.syncStatus"
        )
        families.forEachIndexed { i, method ->
            val generation = (100 + i).toString()
            val response = client.callRaw(method, generation)
            assertEquals("$method must echo the generation: $response", generation, rawGeneration(response))
        }
    }

    @Test
    fun everyErrorKindEchoesTheGeneration() {
        val unknown = client.callRaw("local.definitelyNotAMethod", "201")
        assertEquals(ErrorCodes.METHOD_NOT_FOUND, errorCode(unknown))
        assertEquals("201", rawGeneration(unknown))

        val invalid = client.callRaw("local.sign", "202")
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(invalid))
        assertEquals("202", rawGeneration(invalid))

        val handlerError = client.callRaw(
            "local.getPublicKey", "203", JSONObject().put("keyId", "generation-echo-no-such-key")
        )
        assertEquals(ErrorCodes.KEY_NOT_FOUND, errorCode(handlerError))
        assertEquals("203", rawGeneration(handlerError))
    }

    @Test
    fun theGenerationRoundTripsAcrossTheUint64Range() {
        for (generation in listOf("0", Long.MAX_VALUE.toString(), "18446744073709551615")) {
            assertEquals(generation, rawGeneration(client.callRaw("ping", generation)))
        }
    }

    @Test
    fun aRequestWithoutAGenerationGetsAResponseWithoutOne() {
        assertFalse(client.callRaw("ping", null).contains("\"generation\""))
        assertFalse(client.callRaw("local.definitelyNotAMethod", null).contains("\"generation\""))
    }

    private fun errorCode(response: String): Int =
        JSONObject(response).getJSONObject("error").getInt("code")

    /** The `generation` member's number exactly as written, or null when absent. */
    private fun rawGeneration(response: String): String? =
        Regex(""""generation":(\d+)[,}]""").find(response)?.groupValues?.get(1)
}
