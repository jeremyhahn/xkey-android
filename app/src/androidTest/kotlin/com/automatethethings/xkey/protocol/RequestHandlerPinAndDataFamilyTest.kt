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
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.pin.PinManager
import com.automatethethings.xkey.piv.PivKeyManager
import com.automatethethings.xkey.piv.PivSlot
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.PinSettingsRepository
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/**
 * The PIN, PIV, backup, key-sharing and OATH families, in the request shapes no
 * other suite drives.
 *
 * `ProtocolIntegrationTest` walks each family's happy path and
 * [RequestHandlerErrorPathTest] covers the argument validation in front of
 * them. What is left is the middle: the administrative operations
 * (`SO_PIN` rotation, lockout, reset) that a desktop performs rarely but must
 * get right, the optional fields go-xkms omits when sharing a key, and the
 * failure arms of the OATH handlers.
 *
 * The PIN lockout tests deliberately reduce `maxPinAttempts` to 1 so a single
 * wrong PIN locks the credential; the real five-attempt default would make the
 * test slow and its intent unclear.
 *
 * PIN state lives in a process-wide DataStore, so it is cleared in both
 * [setUp] and [tearDown]; every key, PIV slot, OATH credential and contact this
 * suite persists carries a per-run id and is removed in [tearDown].
 */
@RunWith(AndroidJUnit4::class)
class RequestHandlerPinAndDataFamilyTest {

    companion object {
        private lateinit var context: Context
        private lateinit var handler: RequestHandler
        private lateinit var pinSettings: PinSettingsRepository
        private lateinit var pairedDevices: PairedDeviceRepository

        private const val SO_PIN = "87654321"
        private const val USER_PIN = "123456"

        /** Unique per run so nothing collides with a previous run's leftovers. */
        private val runId = System.currentTimeMillis().toString(36)

        /** The peer identity this suite shares with. */
        private val peerKeyHex =
            ("ba" + java.lang.Long.toHexString(System.nanoTime())).padEnd(64, '0')

        /**
         * A PIV slot this suite owns. `ProtocolIntegrationTest` uses 9a and
         * asserts on its contents, so this suite must not touch it.
         */
        private val pivSlot = PivSlot.DIGITAL_SIGNATURE

        private val nextRequestId = AtomicLong(1)

        private val createdKeyIds = mutableSetOf<String>()
        private val createdOathIds = mutableSetOf<String>()
        private val createdContactLabels = mutableSetOf<String>()

        @JvmStatic
        @BeforeClass
        fun setUp() {
            context = ApplicationProvider.getApplicationContext()
            pinSettings = PinSettingsRepository(context)
            pairedDevices = PairedDeviceRepository(context)

            runBlocking { pinSettings.clearSettings() }

            handler = RequestHandler(
                context = context,
                keystoreManager = KeystoreManager(context),
                biometricLauncher = null,
                sessionAuthManager = SessionAuthManager(),
                pairedDeviceRepository = pairedDevices,
                pinManager = PinManager(PinSettingsRepository(context)),
                pivKeyManager = PivKeyManager(XKeyDatabase.getInstance(context).pivSlotDao())
            )
            pairedDevices.addDevice(peerKeyHex, "PinAndDataFamilyTest Desktop $runId")
        }

        @JvmStatic
        @AfterClass
        fun tearDown() {
            runBlocking {
                val db = XKeyDatabase.getInstance(context)
                val keystoreManager = KeystoreManager(context)
                val softwareKeys = SoftwareKeyStore(context)

                val ids = createdKeyIds.toMutableSet()
                for (entity in db.keyDao().getAll()) {
                    if (entity.keyId.contains(runId)) ids.add(entity.keyId)
                }
                for (keyId in ids) {
                    runCatching { keystoreManager.deleteGeneralKey(keyId) }
                    runCatching { softwareKeys.delete(keyId) }
                    runCatching { db.keyDao().deleteByKeyId(keyId) }
                }

                for (oathId in createdOathIds) {
                    runCatching { db.oathCredentialDao().deleteByOathId(oathId) }
                }
                for (credential in db.oathCredentialDao().getAll()) {
                    if (credential.oathId.contains(runId)) {
                        runCatching { db.oathCredentialDao().deleteByOathId(credential.oathId) }
                    }
                }

                for (contact in db.contactDao().getAll()) {
                    if (createdContactLabels.contains(contact.name)) {
                        runCatching { db.contactDao().deleteById(contact.id) }
                    }
                }

                runCatching { PivKeyManager(db.pivSlotDao()).deleteKey(pivSlot) }
                pinSettings.clearSettings()
            }
            pairedDevices.removeDevice(peerKeyHex)
        }
    }

    /** Every test starts from a cleared PIN store and a confirmed peer. */
    @Before
    fun resetHandlerState() {
        runBlocking { pinSettings.clearSettings() }
        handler.setConnectedDevicePublicKeyHex(peerKeyHex)
        handler.updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.DISABLED,
                attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
            )
        )
    }

    // ------------------------------------------------------------------
    // PIN administration
    // ------------------------------------------------------------------

    /**
     * PKCS#11 defines exactly two PINs. A third name is a caller bug, not a
     * PIN that silently becomes the user's.
     */
    @Test
    fun anUnknownPinTypeIsRejectedByEverySettingOperation() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call(
                "local.pinSet",
                JSONObject().put("pinType", "ADMIN_PIN").put("newPin", "111111")
            ).errorCode()
        )
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call(
                "local.pinChange",
                JSONObject().put("pinType", "ADMIN_PIN")
                    .put("currentPin", "111111").put("newPin", "222222")
            ).errorCode()
        )
    }

    /** The Security Officer authorises User PIN provisioning; a bad SO PIN does not. */
    @Test
    fun settingAUserPinWithTheWrongSoPinIsRejected() {
        setSoPin()

        val response = call(
            "local.pinSet",
            JSONObject().put("pinType", "USER_PIN").put("soPin", "00000000").put("newPin", USER_PIN)
        )

        assertEquals(ErrorCodes.PIN_INCORRECT, response.errorCode())
        assertFalse(
            "a refused set must not mark the User PIN as configured",
            call("local.pinStatus").ok().getBoolean("userPinSet")
        )
    }

    /**
     * Rotating the SO PIN is its own path: `local.pinSet` establishes it,
     * `local.pinChange` rotates it, and the new one has to be the one that
     * works afterwards.
     */
    @Test
    fun theSoPinCanBeRotatedWithItself() {
        setSoPin()
        val rotated = "24681357"

        assertTrue(
            call(
                "local.pinChange",
                JSONObject().put("pinType", "SO_PIN")
                    .put("currentPin", SO_PIN).put("newPin", rotated)
            ).ok().getBoolean("success")
        )

        assertTrue(
            call("local.pinVerify", JSONObject().put("pin", rotated).put("pinType", "SO_PIN"))
                .ok().getBoolean("verified")
        )
        assertEquals(
            "the superseded SO PIN must stop working",
            ErrorCodes.PIN_INCORRECT,
            call("local.pinVerify", JSONObject().put("pin", SO_PIN).put("pinType", "SO_PIN"))
                .errorCode()
        )
    }

    @Test
    fun rotatingTheSoPinWithTheWrongCurrentPinIsRejected() {
        setSoPin()

        val response = call(
            "local.pinChange",
            JSONObject().put("pinType", "SO_PIN")
                .put("currentPin", "00000000").put("newPin", "24681357")
        )

        assertEquals(ErrorCodes.PIN_INCORRECT, response.errorCode())
        assertTrue(
            "the original SO PIN must survive a failed rotation",
            call("local.pinVerify", JSONObject().put("pin", SO_PIN).put("pinType", "SO_PIN"))
                .ok().getBoolean("verified")
        )
    }

    /** Rotating a PIN that was never established is not a silent first-time set. */
    @Test
    fun rotatingASoPinThatWasNeverSetIsRejected() {
        val response = call(
            "local.pinChange",
            JSONObject().put("pinType", "SO_PIN")
                .put("currentPin", SO_PIN).put("newPin", "24681357")
        )

        assertEquals(ErrorCodes.PIN_REQUIRED, response.errorCode())
    }

    /** Clearing a lockout is a Security Officer operation, so it needs the SO PIN. */
    @Test
    fun resettingTheLockoutWithTheWrongSoPinIsRejected() {
        setSoPin()

        assertEquals(
            ErrorCodes.PIN_INCORRECT,
            call("local.pinResetLockout", JSONObject().put("soPin", "00000000")).errorCode()
        )
    }

    /**
     * A locked PIN must say so — and say until when. The desktop renders the
     * remaining lockout from `lockoutUntil`, so the deadline has to travel in
     * the error payload rather than only in the log.
     */
    @Test
    fun aLockedUserPinReportsItsDeadlineAndAttemptCount() {
        setSoPin()
        setUserPin()
        lockAfterOneWrongAttempt()

        // One wrong attempt is now enough to lock it.
        assertEquals(
            ErrorCodes.PIN_INCORRECT,
            call("local.pinVerify", JSONObject().put("pin", "000000").put("pinType", "USER_PIN"))
                .errorCode()
        )

        val locked = call(
            "local.pinVerify",
            JSONObject().put("pin", USER_PIN).put("pinType", "USER_PIN")
        )
        assertEquals(ErrorCodes.PIN_LOCKED, locked.errorCode())

        val data = locked.error?.data
        assertNotNull("a lockout must carry its deadline", data)
        assertTrue("lockoutUntil must be in the future", data!!.getLong("lockoutUntil") > 0)
        assertTrue("the attempt count must be reported", data.getInt("failedAttempts") >= 1)

        assertTrue(
            "pinStatus must agree that the User PIN is locked",
            call("local.pinStatus").ok().getBoolean("userLocked")
        )
    }

    /** A locked PIN cannot be rotated either; that would be a lockout bypass. */
    @Test
    fun aLockedUserPinCannotBeRotated() {
        setSoPin()
        setUserPin()
        lockAfterOneWrongAttempt()

        call("local.pinVerify", JSONObject().put("pin", "000000").put("pinType", "USER_PIN"))

        val response = call(
            "local.pinChange",
            JSONObject().put("pinType", "USER_PIN")
                .put("currentPin", USER_PIN).put("newPin", "654321")
        )

        assertEquals(ErrorCodes.PIN_LOCKED, response.errorCode())
    }

    /** The Security Officer can clear a lockout the user cannot wait out. */
    @Test
    fun theSecurityOfficerCanClearAUserLockout() {
        setSoPin()
        setUserPin()
        lockAfterOneWrongAttempt()

        call("local.pinVerify", JSONObject().put("pin", "000000").put("pinType", "USER_PIN"))
        assertTrue(call("local.pinStatus").ok().getBoolean("userLocked"))

        assertTrue(
            call("local.pinResetLockout", JSONObject().put("soPin", SO_PIN))
                .ok().getBoolean("success")
        )

        assertFalse(call("local.pinStatus").ok().getBoolean("userLocked"))
        assertTrue(
            call("local.pinVerify", JSONObject().put("pin", USER_PIN).put("pinType", "USER_PIN"))
                .ok().getBoolean("verified")
        )
    }

    // ------------------------------------------------------------------
    // PIV
    // ------------------------------------------------------------------

    /**
     * `xkey piv phone-list` shows when a slot was last used, which only appears
     * once the slot has actually signed something.
     */
    @Test
    fun pivListSlotsReportsALastUsedTimeOnceASlotHasSigned() {
        val slotId = pivSlot.hexId
        call("local.pivGenerateKey", JSONObject().put("slot", slotId).put("algorithm", "ES256"))

        assertNull(
            "a freshly generated slot has never been used",
            slotEntry(slotId).opt("lastUsedAt")
        )

        call(
            "local.pivSign",
            JSONObject().put("slot", slotId)
                .put("data", b64("piv last-used probe".toByteArray()))
                .put("algorithm", "ES256")
        )

        val used = slotEntry(slotId)
        assertNotNull("a signed slot must report lastUsedAt", used.opt("lastUsedAt"))
        assertTrue(used.getLong("lastUsedAt") > 0)
    }

    // ------------------------------------------------------------------
    // Backups
    // ------------------------------------------------------------------

    @Test
    fun createBackupWithoutAPayloadIsInvalidParams() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.createBackup", JSONObject().put("label", "no payload")).errorCode()
        )
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.createBackup").errorCode()
        )
    }

    /**
     * `xkey backup restore` without an id means "the latest one", which is what
     * a user recovering a phone actually types.
     */
    @Test
    fun restoreWithoutAnIdReturnsTheMostRecentBackup() {
        val payload = "latest backup payload $runId".toByteArray()
        val created = call(
            "local.createBackup",
            JSONObject().put("backup_data", b64(payload)).put("label", "latest-$runId")
        ).ok()
        assertTrue(created.getBoolean("success"))

        val restored = call("local.restoreBackup", JSONObject()).ok()

        assertTrue(
            "an id-less restore must still name the backup it returned",
            restored.getString("backup_id").isNotEmpty()
        )
        assertTrue(
            "a restore must timestamp the backup",
            restored.getString("created_at").isNotEmpty()
        )

        // Addressed explicitly, the same blob must come back byte for byte.
        val byId = call(
            "local.restoreBackup",
            JSONObject().put("backup_id", created.getString("backup_id"))
        ).ok()
        assertEquals(
            String(payload),
            String(Base64.getDecoder().decode(byId.getString("backup_data")))
        )
    }

    /** A labelled backup echoes the label so the desktop can confirm what it stored. */
    @Test
    fun aLabelledBackupIsAcknowledgedByLabel() {
        val created = call(
            "local.createBackup",
            JSONObject().put("backup_data", b64("labelled".toByteArray()))
                .put("label", "quarterly-$runId")
        ).ok()

        assertTrue(created.getString("message").contains("quarterly-$runId"))
    }

    @Test
    fun anUnlabelledBackupIsAcknowledgedWithoutAMessage() {
        val created = call(
            "local.createBackup",
            JSONObject().put("backup_data", b64("unlabelled".toByteArray()))
        ).ok()

        assertFalse(created.has("message"))
    }

    // ------------------------------------------------------------------
    // Key sharing with omitted optional fields
    // ------------------------------------------------------------------

    /**
     * go-xkms omits `label`, `algorithm` and `backend` when it pushes a key it
     * has no metadata for. The contact still has to be storable — a null name
     * would fail the insert.
     */
    @Test
    fun aSharedPublicKeyWithNoLabelFallsBackToTheKeyId() {
        val keyId = "shared-pub-$runId"
        createdContactLabels.add(keyId)

        val result = call(
            "local.sharePublicKey",
            JSONObject().put("public_key_pem", freshPublicKeyPem()).put("key_id", keyId)
        ).ok()

        assertTrue(result.getBoolean("accepted"))
        assertEquals("the key id identifies the import", keyId, result.getString("import_id"))

        val contact = storedContactNamed(keyId)
        assertNotNull("a contact must have been stored", contact)
        assertEquals("an omitted algorithm is recorded as unknown", "unknown", contact!!.algorithm)
        assertNull("an omitted backend leaves the notes empty", contact.notes)
    }

    /**
     * With neither a label nor a key id there is nothing to name the contact
     * after, so it takes a constant name and the fingerprint identifies the
     * import instead.
     */
    @Test
    fun aSharedPublicKeyWithNoLabelAndNoKeyIdIsNamedByConvention() {
        createdContactLabels.add("shared-key")

        val result = call(
            "local.sharePublicKey",
            JSONObject().put("public_key_pem", freshPublicKeyPem())
        ).ok()

        assertTrue(result.getBoolean("accepted"))
        assertEquals(
            "with no key id the fingerprint identifies the import",
            64,
            result.getString("import_id").length
        )
        assertNotNull(storedContactNamed("shared-key"))
    }

    /** A label wins over the key id when both are present. */
    @Test
    fun aSharedPublicKeyPrefersItsLabel() {
        val label = "Desktop Backup Key $runId"
        createdContactLabels.add(label)

        call(
            "local.sharePublicKey",
            JSONObject()
                .put("public_key_pem", freshPublicKeyPem())
                .put("key_id", "ignored-$runId")
                .put("label", label)
                .put("algorithm", "ES256")
                .put("backend", "yubikey")
        )

        val contact = storedContactNamed(label)
        assertNotNull(contact)
        assertEquals("ES256", contact!!.algorithm)
        assertEquals("the backend is kept as a note", "yubikey", contact.notes)
    }

    /**
     * A symmetric key pushed with no name at all still has to land somewhere,
     * with a size derived from the material rather than left at zero.
     */
    @Test
    fun aSharedSymmetricKeyWithNoNameGetsAGeneratedOne() {
        val material = ByteArray(32) { (it * 3).toByte() }

        val result = call(
            "local.shareSymmetric",
            JSONObject().put("wrapped_key", b64(material))
        ).ok()

        assertTrue(result.getBoolean("accepted"))
        val keyId = result.getString("import_id")
        createdKeyIds.add(keyId)
        assertTrue("a generated id must be recognisable", keyId.startsWith("shared-sym-"))

        val stored = SoftwareKeyStore(context).get(keyId)
        assertNotNull(stored)
        assertEquals("an omitted algorithm defaults to AES", "AES", stored!!.algorithm)
        assertEquals("the size is derived from the material", 256, stored.keySize)
        assertFalse("inbound material is never re-exportable", stored.exportable)
        assertFalse("inbound material is never re-shareable", stored.shareable)
    }

    /** `key_id` names the key when `label` is absent. */
    @Test
    fun aSharedSymmetricKeyFallsBackFromLabelToKeyId() {
        val keyId = "shared-sym-by-id-$runId"
        createdKeyIds.add(keyId)

        val result = call(
            "local.shareSymmetric",
            JSONObject()
                .put("wrapped_key", b64(ByteArray(16) { 9 }))
                .put("key_id", keyId)
                .put("algorithm", "AES128-GCM")
        ).ok()

        assertEquals(keyId, result.getString("import_id"))
        assertEquals("AES128-GCM", SoftwareKeyStore(context).get(keyId)!!.algorithm)
    }

    // ------------------------------------------------------------------
    // OATH
    // ------------------------------------------------------------------

    /**
     * The secret is Base32 on the wire. An undecodable one must be refused
     * rather than stored as a credential that can never produce a code.
     */
    @Test
    fun anOathCredentialWithAnUndecodableSecretIsRefused() {
        val name = "oath-bad-secret-$runId"
        createdOathIds.add(name)

        val response = call(
            "local.oathAdd",
            JSONObject().put(
                "credential",
                JSONObject()
                    .put("name", name)
                    .put("account_name", "user@example.com")
                    .put("secret", "18890!!!not-base32")
            )
        )

        assertFalse("an undecodable secret must not be accepted", response.isSuccess())
    }

    /**
     * HOTP credentials carry a counter instead of a period, and have no
     * expiry — the desktop renders no countdown for them.
     */
    @Test
    fun anHotpCredentialCarriesNoExpiry() {
        val accountName = "hotp-$runId@example.com"
        assertTrue(
            call(
                "local.oathAdd",
                JSONObject().put(
                    "credential",
                    JSONObject()
                        .put("name", "hotp-$runId")
                        .put("issuer", "HotpIssuer")
                        .put("account_name", accountName)
                        .put("secret", "JBSWY3DPEHPK3PXP")
                        .put("type", "hotp")
                        .put("counter", 7)
                        .put("digits", 6)
                )
            ).ok().getBoolean("success")
        )

        val listed = listedCredentialFor(accountName)
        assertNotNull("the HOTP credential must be listed", listed)
        val credentialId = listed!!.getString("name")
        createdOathIds.add(credentialId)

        val code = call(
            "local.oathGenerate",
            JSONObject().put("credential_id", credentialId)
        ).ok()
        assertEquals(6, code.getString("code").length)
        assertEquals("HOTP has no window to expire", 0, code.getInt("expires_in"))
    }

    /**
     * An issuer is optional. It must serialise as a JSON null rather than the
     * string "null", which a desktop would render literally.
     */
    @Test
    fun aCredentialWithNoIssuerListsAJsonNullIssuer() {
        val accountName = "no-issuer-$runId@example.com"
        call(
            "local.oathAdd",
            JSONObject().put(
                "credential",
                JSONObject()
                    .put("name", "no-issuer-$runId")
                    .put("account_name", accountName)
                    .put("secret", "JBSWY3DPEHPK3PXP")
                    .put("type", "totp")
            )
        )

        val listed = listedCredentialFor(accountName)
        assertNotNull(listed)
        createdOathIds.add(listed!!.getString("name"))
        assertTrue("an absent issuer must be a JSON null", listed.isNull("issuer"))
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private fun call(method: String): Response = dispatch(method, null)

    private fun call(method: String, params: JSONObject): Response = dispatch(method, params)

    /**
     * Every request is served for the confirmed peer, as a served transport
     * installs it; the handler-wide peer never stands in for it.
     *
     * Written without default arguments on purpose: a function that carries a
     * default argument and also builds a coroutine lambda has repeatedly
     * crashed the Kotlin JVM backend in these suites
     * (BackendException at RecordEnclosingMethodsLowering).
     */
    private fun dispatch(method: String, params: JSONObject?): Response {
        val request = Request(nextRequestId.getAndIncrement(), method, params)
        val caller = RequestHandler.servedConnection(SessionBindingProvider { null }, peerKeyHex, "test:connection")
        return runBlocking(caller) { handler.handleRequest(request) }
    }

    private fun setSoPin() {
        assertTrue(
            call("local.pinSet", JSONObject().put("pinType", "SO_PIN").put("newPin", SO_PIN))
                .isSuccess()
        )
    }

    private fun setUserPin() {
        assertTrue(
            call(
                "local.pinSet",
                JSONObject().put("pinType", "USER_PIN").put("soPin", SO_PIN).put("newPin", USER_PIN)
            ).isSuccess()
        )
    }

    /** Reduces the attempt budget to one so a single wrong PIN locks the credential. */
    private fun lockAfterOneWrongAttempt() {
        runBlocking {
            pinSettings.updateSettings(pinSettings.getSettings().copy(maxPinAttempts = 1))
        }
    }

    private fun slotEntry(slotId: String): JSONObject {
        val slots = call("local.pivListSlots").ok().getJSONArray("slots")
        return (0 until slots.length())
            .map { slots.getJSONObject(it) }
            .first { it.optString("slot").equals(slotId, ignoreCase = true) }
    }

    private fun listedCredentialFor(accountName: String): JSONObject? {
        val credentials = call("local.oathList").ok().getJSONArray("credentials")
        return (0 until credentials.length())
            .map { credentials.getJSONObject(it) }
            .firstOrNull { it.optString("account_name") == accountName }
    }

    private fun storedContactNamed(name: String) =
        runBlocking {
            XKeyDatabase.getInstance(context).contactDao().getAll().firstOrNull { it.name == name }
        }

    /** A PEM-encoded public key from a throwaway keypair, unique per call. */
    private fun freshPublicKeyPem(): String {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val encoded = generator.generateKeyPair().public.encoded
        return "-----BEGIN PUBLIC KEY-----\n" +
            Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(encoded) +
            "\n-----END PUBLIC KEY-----\n"
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
