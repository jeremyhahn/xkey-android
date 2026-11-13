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

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.ContactDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.ContactEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.coEvery
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import io.mockk.unmockkObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Every key-sharing transfer leaves one audit record naming the caller
 * device (#222): `local.importSharedKey` (a key leaving the phone) records
 * KEY_EXPORTED, `local.shareSymmetric` (key material arriving) KEY_CREATED,
 * and `local.sharePublicKey` (a public key arriving) CONTACT_IMPORTED. No
 * entry carries key bytes, and a request that changes nothing records nothing.
 *
 * This drives the real handler. The audit logger's private `log` is stubbed
 * to capture each entry; the database, the software key store and the
 * Android edges are mocked.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class KeyShareAuditTest {

    private lateinit var keyDao: KeyDao
    private lateinit var contactDao: ContactDao
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var handler: RequestHandler
    private val entries = mutableListOf<AuditLogEntity>()

    @get:Rule
    val tmp = TemporaryFolder()

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)

        mockkStatic(android.util.Base64::class)
        every { android.util.Base64.encodeToString(any(), any()) } answers {
            Base64.getEncoder().encodeToString(firstArg<ByteArray>())
        }

        mockkObject(AuditLogger)
        every { AuditLogger["log"](any<AuditLogEntity>()) } answers {
            entries += firstArg<AuditLogEntity>()
            Unit
        }

        keyDao = mockk(relaxed = true)
        coEvery { keyDao.getByKeyId(any()) } returns null
        contactDao = mockk(relaxed = true)
        coEvery { contactDao.getByFingerprint(any()) } returns null
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        every { database.contactDao() } returns contactDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        // SoftwareKeyStore's default cipher opens AndroidKeyStore as it is
        // built, which a constructor mock does not skip.
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        mockkConstructor(SoftwareKeyStore::class)
        every { anyConstructed<SoftwareKeyStore>().get(any()) } returns null
        every { anyConstructed<SoftwareKeyStore>().contains(any()) } returns false
        every { anyConstructed<SoftwareKeyStore>().put(any()) } just runs

        Dispatchers.setMain(UnconfinedTestDispatcher())

        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns tmp.root
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        val pairedDevices = mockk<PairedDeviceRepository>(relaxed = true)
        every { pairedDevices.getDevice(PEER) } returns PairedDeviceData(PEER, PEER_NAME, 0L)

        keystoreManager = mockk(relaxed = true)
        every { keystoreManager.getPublicKeyPEM(any()) } returns null
        handler = RequestHandler(
            context = context,
            keystoreManager = keystoreManager,
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices
        )
        handler.setConnectedDevicePublicKeyHex(PEER)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    // -----------------------------------------------------------------
    // local.importSharedKey: a key leaving the phone
    // -----------------------------------------------------------------

    @Test
    fun exportingSoftwareKeyMaterialRecordsOneRawExport() = runTest {
        givenSoftwareKey(exportable = true, shareable = true)

        val result = success(handler.handleRawRequest(importSharedKey()))

        assertEquals(Base64.getEncoder().encodeToString(MATERIAL), result.getString("wrapped_key"))
        assertTrue(result.getBoolean("exportable"))
        val entry = single(AuditOperationType.KEY_EXPORTED)
        assertTrue(entry.success)
        assertEquals(KEY_ID, entry.keyId)
        assertEquals(PEER, entry.deviceId)
        assertEquals(PEER_NAME, entry.deviceName)
        assertEquals("raw", JSONObject(entry.details!!).getString("format"))
        assertNoKeyBytes(entry)
    }

    @Test
    fun sharingAHardwareKeyRecordsOnePublicExport() = runTest {
        every { keystoreManager.getPublicKeyPEM(KEY_ID) } returns "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"
        coEvery { keyDao.getByKeyId(KEY_ID) } returns keyEntity(SharingPolicyType.ALL_PEERS)

        val result = success(handler.handleRawRequest(importSharedKey()))

        assertEquals("public", result.getString("key_type"))
        val entry = single(AuditOperationType.KEY_EXPORTED)
        assertTrue(entry.success)
        assertEquals(PEER, entry.deviceId)
        assertEquals("public", JSONObject(entry.details!!).getString("format"))
    }

    @Test
    fun aPolicyRefusalRecordsOneFailedExport() = runTest {
        givenSoftwareKey(exportable = true, shareable = true, policy = SharingPolicyType.PRIVATE)

        val response = Response.fromJson(handler.handleRawRequest(importSharedKey()))

        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        val entry = single(AuditOperationType.KEY_EXPORTED)
        assertFalse(entry.success)
        assertEquals(PEER, entry.deviceId)
        assertTrue(entry.errorMessage!!.isNotBlank())
        assertNoKeyBytes(entry)
    }

    @Test
    fun anUnknownKeyRecordsNothing() = runTest {
        val response = Response.fromJson(handler.handleRawRequest(importSharedKey()))

        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.error?.code)
        assertTrue("no entry for an unknown key: $entries", entries.isEmpty())
    }

    // -----------------------------------------------------------------
    // local.shareSymmetric: key material arriving
    // -----------------------------------------------------------------

    @Test
    fun receivingSymmetricKeyMaterialRecordsOneKeyCreated() = runTest {
        val result = success(handler.handleRawRequest(shareSymmetric()))

        assertTrue(result.getBoolean("accepted"))
        assertEquals(KEY_ID, result.getString("import_id"))
        val entry = single(AuditOperationType.KEY_CREATED)
        assertTrue(entry.success)
        assertEquals(KEY_ID, entry.keyId)
        assertEquals(PEER, entry.deviceId)
        assertEquals(PEER_NAME, entry.deviceName)
        assertNoKeyBytes(entry)
    }

    @Test
    fun aDuplicateSymmetricKeyRecordsNothing() = runTest {
        every { anyConstructed<SoftwareKeyStore>().contains(KEY_ID) } returns true

        val response = Response.fromJson(handler.handleRawRequest(shareSymmetric()))

        assertEquals(ErrorCodes.KEY_EXISTS, response.error?.code)
        assertTrue("no entry for a refused duplicate: $entries", entries.isEmpty())
    }

    // -----------------------------------------------------------------
    // local.sharePublicKey: a public key arriving
    // -----------------------------------------------------------------

    @Test
    fun receivingAPublicKeyRecordsOneContactImport() = runTest {
        val result = success(handler.handleRawRequest(sharePublicKey()))

        assertTrue(result.getBoolean("accepted"))
        val entry = single(AuditOperationType.CONTACT_IMPORTED)
        assertTrue(entry.success)
        assertEquals(PEER, entry.deviceId)
        assertEquals("shared", JSONObject(entry.details!!).getString("source"))
    }

    @Test
    fun aRepeatedPublicKeyRecordsNothing() = runTest {
        coEvery { contactDao.getByFingerprint(any()) } returns mockk<ContactEntity>(relaxed = true)

        val result = success(handler.handleRawRequest(sharePublicKey()))

        assertTrue(result.getBoolean("accepted"))
        assertTrue("no entry for a known key: $entries", entries.isEmpty())
    }

    // -----------------------------------------------------------------
    // With the logger not initialized, every transfer answers as before
    // -----------------------------------------------------------------

    @Test
    fun anUninitializedLoggerChangesNoAnswer() = runTest {
        unmockkObject(AuditLogger)
        givenSoftwareKey(exportable = true, shareable = true)

        val exported = success(handler.handleRawRequest(importSharedKey()))
        assertEquals(Base64.getEncoder().encodeToString(MATERIAL), exported.getString("wrapped_key"))

        every { anyConstructed<SoftwareKeyStore>().get(any()) } returns null
        coEvery { keyDao.getByKeyId(any()) } returns null
        val symmetric = success(handler.handleRawRequest(shareSymmetric(keyId = "other-sym")))
        assertEquals("other-sym", symmetric.getString("import_id"))

        val contact = success(handler.handleRawRequest(sharePublicKey()))
        assertTrue(contact.getBoolean("accepted"))
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun givenSoftwareKey(
        exportable: Boolean,
        shareable: Boolean,
        policy: SharingPolicyType = SharingPolicyType.ALL_PEERS
    ) {
        every { anyConstructed<SoftwareKeyStore>().get(KEY_ID) } returns SoftwareKey(
            keyId = KEY_ID,
            algorithm = "AES",
            keyType = "symmetric",
            keySize = MATERIAL.size * 8,
            exportable = exportable,
            shareable = shareable,
            material = MATERIAL
        )
        coEvery { keyDao.getByKeyId(KEY_ID) } returns
            keyEntity(policy, exportable = exportable, shareable = shareable)
    }

    private fun keyEntity(
        policy: SharingPolicyType,
        exportable: Boolean = false,
        shareable: Boolean = false
    ) = KeyEntity(
        keyId = KEY_ID,
        keyType = "symmetric",
        algorithm = "AES",
        label = KEY_ID,
        keySizeBits = 256,
        exportable = exportable,
        shareable = shareable,
        sharingPolicy = policy,
        source = "software"
    )

    private fun importSharedKey(): ByteArray = Request(
        id = 1,
        method = MethodNames.LOCAL_IMPORT_SHARED_KEY,
        params = JSONObject().put("key_id", KEY_ID)
    ).toJson()

    private fun shareSymmetric(keyId: String = KEY_ID): ByteArray = Request(
        id = 2,
        method = MethodNames.LOCAL_SHARE_SYMMETRIC,
        params = JSONObject()
            .put("key_id", keyId)
            .put("algorithm", "AES")
            .put("wrapped_key", Base64.getEncoder().encodeToString(MATERIAL))
    ).toJson()

    private fun sharePublicKey(): ByteArray = Request(
        id = 3,
        method = MethodNames.LOCAL_SHARE_PUBLIC_KEY,
        params = JSONObject()
            .put("public_key_pem", publicKeyPem)
            .put("key_id", "desk-ec")
            .put("algorithm", "ES256")
    ).toJson()

    private fun success(bytes: ByteArray): JSONObject {
        val response = Response.fromJson(bytes)
        assertNull("expected success: ${response.error?.message}", response.error)
        return response.result!!
    }

    private fun single(type: AuditOperationType): AuditLogEntity {
        assertEquals("one entry expected: $entries", 1, entries.size)
        val entry = entries.single()
        assertEquals(type, entry.operationType)
        return entry
    }

    /** Neither the material nor its encodings may appear in any field. */
    private fun assertNoKeyBytes(entry: AuditLogEntity) {
        val text = entry.toString() + (entry.details ?: "")
        val b64 = Base64.getEncoder().encodeToString(MATERIAL)
        val hex = MATERIAL.joinToString("") { "%02x".format(it) }
        assertFalse("key material in the entry: $text", text.contains(b64))
        assertFalse("key material in the entry: $text", text.contains(hex, ignoreCase = true))
    }

    private companion object {
        const val PEER = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
        const val PEER_NAME = "Desk"
        const val KEY_ID = "shared-aes"
        val MATERIAL = ByteArray(32) { (0x40 + it).toByte() }

        val publicKeyPem: String by lazy {
            val der = KeyPairGenerator.getInstance("EC").apply { initialize(256) }
                .generateKeyPair().public.encoded
            "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der) +
                "\n-----END PUBLIC KEY-----"
        }
    }
}
