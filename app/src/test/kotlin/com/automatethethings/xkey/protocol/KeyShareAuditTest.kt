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
import android.content.SharedPreferences
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
import com.automatethethings.xkey.settings.DeviceLookup
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.ContactDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
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
import io.mockk.verify
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
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
    private lateinit var pairedDevices: PairedDeviceRepository
    private lateinit var context: Context
    private lateinit var grants: KeySharingPolicyDao
    private val policies = mockk<com.automatethethings.xkey.storage.dao.KeyPolicyDao>(relaxed = true) {
        coEvery { deletion(any()) } returns null
        // No policy row: the store enforces the key row's own policy.
        coEvery { policyRow(any()) } returns null
    }
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
        // No delete of any key is pending: a relaxed DAO would report one.
        every { database.keyPolicyDao() } returns policies
        grants = mockk(relaxed = true)
        coEvery { grants.isKeySharedWithPeer(any(), any()) } returns false
        coEvery { grants.isPeerGranted(any(), any()) } returns false
        every { database.keySharingPolicyDao() } returns grants
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

        context = mockk(relaxed = true)
        every { context.filesDir } returns tmp.root
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        pairedDevices = mockk(relaxed = true)
        every { pairedDevices.lookupDevice(any()) } returns DeviceLookup.NotPaired
        every { pairedDevices.lookupDevice(PEER) } returns DeviceLookup.Paired(PairedDeviceData(PEER, PEER_NAME, 0L))
        every { pairedDevices.lookupDevice(USB_PEER) } returns
            DeviceLookup.Paired(PairedDeviceData(USB_PEER, USB_PEER_NAME, 0L))

        keystoreManager = mockk(relaxed = true)
        every { keystoreManager.getPublicKeyPEM(any(), any()) } returns null
        // No Keystore key holds an id: a share reads the general namespace.
        every { keystoreManager.exportKind(any()) } returns com.automatethethings.xkey.crypto.UserKeyKind.GENERAL
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

        val result = success(served(importSharedKey()))

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
        every { keystoreManager.getPublicKeyPEM(KEY_ID, any()) } returns "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"
        coEvery { keyDao.getByKeyId(KEY_ID) } returns keyEntity(SharingPolicyType.ALL_PEERS)

        val result = success(served(importSharedKey()))

        assertEquals("public", result.getString("key_type"))
        val entry = single(AuditOperationType.KEY_EXPORTED)
        assertTrue(entry.success)
        assertEquals(PEER, entry.deviceId)
        assertEquals("public", JSONObject(entry.details!!).getString("format"))
    }

    /** A shareable software key that is not exportable leaves as metadata, and is recorded as such. */
    @Test
    fun sharingASoftwareKeyWithoutItsMaterialRecordsOneMetadataExport() = runTest {
        givenSoftwareKey(exportable = false, shareable = true)

        val result = success(served(importSharedKey()))

        assertFalse(result.getBoolean("exportable"))
        assertFalse("no material leaves: $result", result.has("wrapped_key"))
        val entry = single(AuditOperationType.KEY_EXPORTED)
        assertTrue(entry.success)
        assertEquals(KEY_ID, entry.keyId)
        assertEquals(PEER, entry.deviceId)
        assertEquals(PEER_NAME, entry.deviceName)
        assertEquals("metadata", JSONObject(entry.details!!).getString("format"))
        assertNoKeyBytes(entry)
    }

    /**
     * The paired-device store cannot be read (encrypted prefs throw). Every
     * transfer still runs and is recorded against its peer, with no name:
     * the record never depends on the name lookup.
     */
    @Test
    fun anUnreadablePairedDeviceStoreStillRecordsEveryTransfer() = runTest {
        every { pairedDevices.lookupDevice(any()) } returns
            DeviceLookup.Unreadable(SecurityException("keystore unavailable"))
        givenSoftwareKey(exportable = true, shareable = true)

        success(served(sharePublicKey()))
        success(served(shareSymmetric(keyId = "other-sym")))
        success(served(importSharedKey()))

        assertEquals(
            listOf(
                AuditOperationType.CONTACT_IMPORTED,
                AuditOperationType.KEY_CREATED,
                AuditOperationType.KEY_EXPORTED
            ),
            entries.map { it.operationType }
        )
        entries.forEach {
            assertTrue("recorded: $it", it.success)
            assertEquals("entry names the peer: $it", PEER, it.deviceId)
            assertNull("no name without the store: $it", it.deviceName)
        }
    }

    /**
     * The same holds for a key use record, which shares the one name lookup.
     * The attestation policy's read comes first and succeeds; the store then
     * fails for the record's name lookup, after the key was used.
     */
    @Test
    fun aStoreFailingAfterAKeyUseStillRecordsIt() = runTest {
        every { pairedDevices.lookupDevice(any()) } returns
            DeviceLookup.Paired(PairedDeviceData(PEER, PEER_NAME, 0L)) andThen
            DeviceLookup.Unreadable(SecurityException("keystore unavailable"))
        coEvery { keystoreManager.symmetricEncrypt(KEY_ID, any(), any()) } returns ByteArray(16)

        success(served(keyUse(MethodNames.LOCAL_SYMMETRIC_ENCRYPT, "plaintext")))

        val entry = single(AuditOperationType.ENCRYPTION_REQUEST)
        assertEquals(PEER, entry.deviceId)
        assertNull(entry.deviceName)
    }

    /**
     * A paired-device store that cannot be read (encrypted prefs throw) is
     * not a peer with no record: the phone cannot tell whether the peer's
     * settings require a current attestation, so key use and key
     * attestation are refused rather than let through.
     */
    @Test
    fun anUnreadableStoreRefusesKeyUseAndKeyAttestation() = runTest {
        val unreadable = mockk<SharedPreferences>(relaxed = true)
        every { unreadable.getString(any(), any()) } throws SecurityException("keystore unavailable")
        handler = RequestHandler(
            context = context,
            keystoreManager = keystoreManager,
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = PairedDeviceRepository(unreadable)
        )
        coEvery { keystoreManager.symmetricEncrypt(KEY_ID, any(), any()) } returns ByteArray(16)

        val keyUse = Response.fromJson(served(keyUse(MethodNames.LOCAL_SYMMETRIC_ENCRYPT, "plaintext")))
        assertEquals(ErrorCodes.DEVICE_ATTESTATION_REQUIRED, keyUse.error?.code)

        val attest = Request(id = 5, method = "local.attestKey", params = JSONObject().put("keyId", KEY_ID)).toJson()
        assertEquals(ErrorCodes.DEVICE_ATTESTATION_REQUIRED, Response.fromJson(served(attest)).error?.code)
    }

    @Test
    fun aPolicyRefusalRecordsOneFailedExport() = runTest {
        givenSoftwareKey(exportable = true, shareable = true, policy = SharingPolicyType.PRIVATE)

        val response = Response.fromJson(served(importSharedKey()))

        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        val entry = single(AuditOperationType.KEY_EXPORTED)
        assertFalse(entry.success)
        assertEquals(PEER, entry.deviceId)
        assertTrue(entry.errorMessage!!.isNotBlank())
        assertNoKeyBytes(entry)
    }

    /**
     * A refused hardware key is recorded with the type it is stored with, as
     * its granted export is, never "public": the audit screen filters by key
     * type, so a denied export must sit under its key's filter.
     */
    @Test
    fun aRefusedHardwareExportRecordsTheStoredKeyType() = runTest {
        every { keystoreManager.getPublicKeyPEM(KEY_ID, any()) } returns "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"
        coEvery { keyDao.getByKeyId(KEY_ID) } returns
            keyEntity(SharingPolicyType.PRIVATE, keyType = "signing")

        val response = Response.fromJson(served(importSharedKey()))

        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        val entry = single(AuditOperationType.KEY_EXPORTED)
        assertFalse(entry.success)
        assertEquals("signing", entry.keyType)
        assertEquals("public", JSONObject(entry.details!!).getString("format"))

        entries.clear()
        coEvery { keyDao.getByKeyId(KEY_ID) } returns
            keyEntity(SharingPolicyType.ALL_PEERS, keyType = "signing")
        success(served(importSharedKey()))
        assertEquals("a granted export reads the same type", "signing", single(AuditOperationType.KEY_EXPORTED).keyType)
    }

    /** Every export record, granted or refused, takes its keyType from the one stored-type lookup. */
    @Test
    fun everyExportRecordTakesTheStoredKeyType() {
        val source = handlerSource()
        val calls = Regex("AuditLogger\\.logKeyExported\\(([^)]*)\\)").findAll(source).toList()
        assertTrue("export records found: ${calls.size}", calls.size >= 2)
        for (call in calls) {
            assertTrue(
                "an export record takes keyType from auditKeyType: ${call.groupValues[1].trim()}",
                Regex("keyType = keyType,").containsMatchIn(call.groupValues[1])
            )
        }
        assertTrue(
            "the export's keyType is the stored type",
            "val keyType = auditKeyType(keyId, software)" in source
        )
    }

    @Test
    fun anUnknownKeyRecordsNothing() = runTest {
        val response = Response.fromJson(served(importSharedKey()))

        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.error?.code)
        assertTrue("no entry for an unknown key: $entries", entries.isEmpty())
    }

    // -----------------------------------------------------------------
    // local.shareSymmetric: key material arriving
    // -----------------------------------------------------------------

    @Test
    fun receivingSymmetricKeyMaterialRecordsOneKeyCreated() = runTest {
        val result = success(served(shareSymmetric()))

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

        val response = Response.fromJson(served(shareSymmetric()))

        assertEquals(ErrorCodes.KEY_EXISTS, response.error?.code)
        assertTrue("no entry for a refused duplicate: $entries", entries.isEmpty())
    }

    // -----------------------------------------------------------------
    // local.sharePublicKey: a public key arriving
    // -----------------------------------------------------------------

    @Test
    fun receivingAPublicKeyRecordsOneContactImport() = runTest {
        val result = success(served(sharePublicKey()))

        assertTrue(result.getBoolean("accepted"))
        val entry = single(AuditOperationType.CONTACT_IMPORTED)
        assertTrue(entry.success)
        assertEquals(PEER, entry.deviceId)
        assertEquals("shared", JSONObject(entry.details!!).getString("source"))
    }

    @Test
    fun aRepeatedPublicKeyRecordsNothing() = runTest {
        coEvery { contactDao.getByFingerprint(any()) } returns mockk<ContactEntity>(relaxed = true)

        val result = success(served(sharePublicKey()))

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

        val exported = success(served(importSharedKey()))
        assertEquals(Base64.getEncoder().encodeToString(MATERIAL), exported.getString("wrapped_key"))

        every { anyConstructed<SoftwareKeyStore>().get(any()) } returns null
        coEvery { keyDao.getByKeyId(any()) } returns null
        val symmetric = success(served(shareSymmetric(keyId = "other-sym")))
        assertEquals("other-sym", symmetric.getString("import_id"))

        val contact = success(served(sharePublicKey()))
        assertTrue(contact.getBoolean("accepted"))
    }

    // -----------------------------------------------------------------
    // The peer is the request's own connection, never the last one paired
    // -----------------------------------------------------------------

    /**
     * Desktop A stays connected over BLE while desktop B pairs over USB last,
     * which overwrites the handler-wide peer. A's transfers must still be
     * authorized for, and recorded against, A.
     */
    @Test
    fun aSecondTransportPairedLastIsNeverTheRecordedPeer() = runTest {
        handler.setConnectedDevicePublicKeyHex(USB_PEER)
        givenSoftwareKey(exportable = true, shareable = true)

        success(served(sharePublicKey(), peer = PEER))
        success(served(shareSymmetric(keyId = "other-sym"), peer = PEER))
        success(served(importSharedKey(), peer = PEER))

        assertEquals(
            listOf(
                AuditOperationType.CONTACT_IMPORTED,
                AuditOperationType.KEY_CREATED,
                AuditOperationType.KEY_EXPORTED
            ),
            entries.map { it.operationType }
        )
        entries.forEach {
            assertEquals("entry names the caller: $it", PEER, it.deviceId)
            assertEquals("entry names the caller: $it", PEER_NAME, it.deviceName)
        }
    }

    /** B's transfer, served on B's own connection, names B and not A. */
    @Test
    fun eachConnectionRecordsItsOwnPeer() = runTest {
        handler.setConnectedDevicePublicKeyHex(PEER)

        success(served(sharePublicKey(), peer = USB_PEER))

        val entry = single(AuditOperationType.CONTACT_IMPORTED)
        assertEquals(USB_PEER, entry.deviceId)
        assertEquals(USB_PEER_NAME, entry.deviceName)
    }

    /**
     * A SELECTED_PEERS key granted to A alone. A, served on its own
     * connection while B is the handler-wide peer, gets the key; B, served on
     * its own connection while A is the handler-wide peer, is refused. The
     * grant is checked for the caller, never for the handler-wide peer.
     */
    @Test
    fun aSelectedPeerGrantFollowsTheCallerNotTheHandlerWidePeer() = runTest {
        givenSoftwareKey(exportable = true, shareable = true, policy = SharingPolicyType.SELECTED_PEERS)
        coEvery { grants.isKeySharedWithPeer(KEY_ID, PEER) } returns true
        coEvery { grants.isPeerGranted(KEY_ID, PEER) } returns true

        handler.setConnectedDevicePublicKeyHex(USB_PEER)
        val granted = success(served(importSharedKey(), peer = PEER))
        assertEquals(Base64.getEncoder().encodeToString(MATERIAL), granted.getString("wrapped_key"))

        handler.setConnectedDevicePublicKeyHex(PEER)
        val refused = Response.fromJson(served(importSharedKey(), peer = USB_PEER))
        assertEquals(ErrorCodes.OPERATION_DENIED, refused.error?.code)

        assertEquals(listOf(true to PEER, false to USB_PEER), entries.map { it.success to it.deviceId })
    }

    /**
     * A request that names no connection (an in-process caller) is answered
     * for the handler-wide peer, the one fallback of
     * `currentPeerPublicKeyHex`; a served connection never takes it.
     */
    @Test
    fun aRequestWithNoConnectionFallsBackToTheHandlerWidePeer() = runTest {
        handler.setConnectedDevicePublicKeyHex(PEER)

        success(handler.handleRawRequest(sharePublicKey()))

        assertEquals(PEER, single(AuditOperationType.CONTACT_IMPORTED).deviceId)
    }

    /**
     * A served connection that authenticated no peer is refused as an
     * anonymous peer, not answered as a protocol failure, even while another
     * desktop is the handler-wide peer.
     */
    @Test
    fun aConnectionWithNoPeerKeyIsRefusedAsAnonymous() = runTest {
        handler.setConnectedDevicePublicKeyHex(USB_PEER)

        val response = Response.fromJson(served(sharePublicKey(), peer = null))

        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        assertTrue("no entry without a caller peer: $entries", entries.isEmpty())
    }

    // -----------------------------------------------------------------
    // Cancellation never splits a stored contact from its record
    // -----------------------------------------------------------------

    /**
     * The connection drops (the request's job is cancelled) while the contact
     * insert is in flight. Like a Room insert, the fake stores the row and
     * then resumes into the cancellation. The row has landed, so its
     * CONTACT_IMPORTED record must land too: both persist or neither does.
     *
     * The fake is a real override, not a mockk answer: mockk runs a
     * suspending answer in its own runBlocking, so cancellation there never
     * reaches the request.
     */
    @Test
    fun aShareCancelledMidInsertStillRecordsTheStoredContact() = runTest {
        val stored = mutableListOf<ContactEntity>()
        lateinit var request: Job
        givenContactDao(object : ContactDao by contactDao {
            override suspend fun insert(contact: ContactEntity): Long {
                stored += contact
                request.cancel()
                yield()
                return 1L
            }
        })

        request = launch { served(sharePublicKey()) }
        request.join()

        assertTrue("the request was cancelled", request.isCancelled)
        assertEquals("the contact landed", 1, stored.size)
        assertEquals(PEER, single(AuditOperationType.CONTACT_IMPORTED).deviceId)
    }

    /** Cancelled before the insert: neither the contact nor a record persists. */
    @Test
    fun aShareCancelledBeforeInsertStoresAndRecordsNothing() = runTest {
        val stored = mutableListOf<ContactEntity>()
        lateinit var request: Job
        givenContactDao(object : ContactDao by contactDao {
            override suspend fun getByFingerprint(fingerprint: String): ContactEntity? {
                request.cancel()
                yield()
                return null
            }

            override suspend fun insert(contact: ContactEntity): Long {
                stored += contact
                return 1L
            }
        })

        request = launch { served(sharePublicKey()) }
        request.join()

        assertTrue("the request was cancelled", request.isCancelled)
        assertTrue("no contact: $stored", stored.isEmpty())
        assertTrue("no entry: $entries", entries.isEmpty())
    }

    /**
     * Cancelled with no suspension point between the cancellation and the
     * write: the request is already cancelled when it reaches the
     * non-cancellable step, which must refuse it rather than store a contact
     * the caller never sees accepted.
     */
    @Test
    fun aContactShareAlreadyCancelledAtTheWriteStoresAndRecordsNothing() = runTest {
        val stored = mutableListOf<ContactEntity>()
        lateinit var request: Job
        givenContactDao(object : ContactDao by contactDao {
            override suspend fun getByFingerprint(fingerprint: String): ContactEntity? {
                request.cancel()
                return null
            }

            override suspend fun insert(contact: ContactEntity): Long {
                stored += contact
                return 1L
            }
        })

        request = launch { served(sharePublicKey()) }
        request.join()

        assertTrue("the request was cancelled", request.isCancelled)
        assertTrue("no contact: $stored", stored.isEmpty())
        assertTrue("no entry: $entries", entries.isEmpty())
    }

    /** The same for arriving key material: a cancelled request stores no key. */
    @Test
    fun aSymmetricShareAlreadyCancelledAtTheWriteStoresAndRecordsNothing() = runTest {
        lateinit var request: Job
        every { anyConstructed<SoftwareKeyStore>().contains(any()) } answers {
            request.cancel()
            false
        }

        request = launch { served(shareSymmetric()) }
        request.join()

        assertTrue("the request was cancelled", request.isCancelled)
        verify(exactly = 0) { anyConstructed<SoftwareKeyStore>().put(any()) }
        assertTrue("no entry: $entries", entries.isEmpty())
    }

    private fun givenContactDao(dao: ContactDao) {
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        every { database.contactDao() } returns dao
        every { database.keyPolicyDao() } returns policies
        every { XKeyDatabase.getInstance(any()) } returns database
    }

    /**
     * Every share write and the audit record naming it run inside the one
     * non-cancellable choke point, `persistAudited`; a share handler that
     * writes or records outside it fails here.
     */
    @Test
    fun everyShareWriteRunsWithItsRecordInTheChokePoint() {
        val source = handlerSource()
        val choke = Regex(
            "private suspend fun <T> persistAudited\\([^)]*\\)[^{]*\\{\\s*" +
                "currentCoroutineContext\\(\\)\\.ensureActive\\(\\)\\s*" +
                "return withContext\\(NonCancellable\\)"
        )
        assertTrue(
            "persistAudited refuses a cancelled request, then runs under NonCancellable",
            choke.containsMatchIn(source)
        )
        assertEquals(
            "persistAudited is the one non-cancellable write and record",
            1,
            Regex("withContext\\(NonCancellable\\)").findAll(source).count()
        )
        // The sharing-policy change is written by KeyPolicyStore.setPolicy,
        // which runs the decision's audit after its commit, uncancellably:
        // the handler's one policy write passes a decision that records it.
        val setPolicyStart = source.indexOf("private suspend fun handleLocalSetKeyPolicy(")
        assertTrue("handleLocalSetKeyPolicy found", setPolicyStart >= 0)
        val setPolicy = source.substring(setPolicyStart, source.indexOf("\n    }\n", setPolicyStart))
        assertTrue(
            "the sharing-policy change records through the store decision's audit",
            Regex(
                "KeyPolicyStore\\.RemoteDecision\\([^)]*\\)\\s*\\{\\s*replaced ->[^}]*" +
                    "AuditLogger\\.logKeySharingChanged\\("
            ).containsMatchIn(setPolicy)
        )
        assertTrue(
            "the sharing-policy change is written through the store with that decision",
            Regex("KeySharingPeers\\.setKeyPolicy\\([^{}]*?decision = decision\\s*\\)").containsMatchIn(setPolicy)
        )
        assertFalse(
            "no sharing-policy write bypasses the store",
            Regex("keyDao\\.(compareAndSetSharingPolicy|setSharingPolicy|updateSharingPolicy)\\(").containsMatchIn(source)
        )
        for ((fn, write, record) in listOf(
            Triple("handleSharePublicKey", "dao.insert(", "AuditLogger.logContactImported("),
            Triple("handleShareSymmetric", "store.put(", "AuditLogger.logKeyCreated(")
        )) {
            val start = source.indexOf("private suspend fun $fn(")
            assertTrue("$fn found", start >= 0)
            val body = source.substring(start, source.indexOf("\n    }\n", start))
            val gate = body.indexOf("persistAudited(")
            assertTrue("$fn uses persistAudited", gate >= 0)
            for (call in listOf(write, record)) {
                assertEquals("$fn makes one $call", 1, Regex(Regex.escape(call)).findAll(body).count())
                assertTrue("$fn runs $call inside persistAudited", body.indexOf(call) > gate)
            }
        }
    }

/**
     * #255 review: every crypto use of a software key reads its material
     * through `withUsableSoftwareKey`, inside the store's use gate, so a use
     * that waited out a delete never runs with bytes read before it. Only
     * the choke point itself, the audit's key-type read and the share
     * handler's (gated at dispatch, no crypto) read the store.
     */
    @Test
    fun everySoftwareKeyUseReadsItsMaterialInsideTheUseGate() {
        val source = handlerSource()
        val members = source.split(Regex("\n(?=    (?:(?:private|internal|public|override) )*(?:suspend )?(?:inline )?fun )"))
        val readers = members.filter { "SoftwareKeyStore(context).get(" in it }
            .map { Regex("fun (?:<[^>]*> )?(\\w+)").find(it)!!.groupValues[1] }
        assertEquals(setOf("withUsableSoftwareKey", "auditKeyType", "handleImportSharedKey"), readers.toSet())
        assertTrue(
            "the choke point reads the record inside withUsableKey",
            Regex(
                "fun <T> withUsableSoftwareKey\\([\\s\\S]*?withUsableKey\\([^)]*\\)\\s*\\{\\s*" +
                    "com\\.automatethethings\\.xkey\\.crypto\\.SoftwareKeyStore\\(context\\)\\.get\\("
            ).containsMatchIn(source)
        )
        for (fn in listOf("handleLocalSymmetricEncrypt", "handleLocalSymmetricDecrypt", "handleLocalHMAC")) {
            val start = source.indexOf("private suspend fun $fn(")
            assertTrue("$fn found", start >= 0)
            assertTrue("$fn uses withUsableSoftwareKey", "withUsableSoftwareKey(" in source.substring(start, source.indexOf("\n    }\n", start)))
        }
    }

    /**
     * Every audit record takes the peer's paired name from `auditPeerName`,
     * which never throws: no audit path reads the paired-device store itself,
     * so a store that cannot be read never suppresses a record.
     */
    @Test
    fun everyAuditDeviceNameGoesThroughAuditPeerName() {
        val source = handlerSource()
            .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
            .replace(Regex("//[^\n]*"), "")
        val members = source.split(Regex("\n(?=    (?:(?:private|internal|public|override) )*(?:suspend )?fun )"))
        val memberFun = Regex("^\\s*(?:(?:private|internal|public|override) )*(?:suspend )?fun (\\w+)")
        fun nameOf(chunk: String) = memberFun.find(chunk)?.groupValues?.get(1)

        // One device read, lookupDevice, which keeps "unreadable" apart from
        // "not paired": the attestation policy reads it to decide (and fails
        // closed), the audit name best-effort. Nothing reads getDevice, whose
        // null cannot say which.
        assertFalse("the handler never reads getDevice", ".getDevice(" in source)
        assertEquals(
            setOf("auditPeerName", "isDeviceAttestationCurrent"),
            members.filter { ".lookupDevice(" in it }.mapNotNull { nameOf(it) }.toSet()
        )
        val lookup = members.single { nameOf(it) == "auditPeerName" }
        assertTrue("auditPeerName catches a failed lookup", "catch (e: Exception)" in lookup)
        val attestation = members.single { nameOf(it) == "isDeviceAttestationCurrent" }
        assertFalse("the attestation policy records nothing", "AuditLogger.log" in attestation)
        assertTrue(
            "the attestation policy refuses an unreadable store",
            Regex("is DeviceLookup\\.Unreadable\\) \\{[^}]*return false", RegexOption.DOT_MATCHES_ALL)
                .containsMatchIn(attestation)
        )

        val allowed = Regex("(?:auditPeerName\\(\\w+\\)|peerName|peer\\?\\.deviceName|caller\\.deviceName|Build\\.MODEL|deviceName)\\)*")
        assertTrue(
            "a key-use caller is named through auditPeerName",
            "AuditCaller(peer, auditPeerName(peer))" in source
        )
        val auditing = members.filter { "AuditLogger.log" in it }
        assertTrue("audit paths found: ${auditing.size}", auditing.size >= 8)
        for (fn in auditing) {
            Regex("deviceName = ([^,\n]+)").findAll(fn).forEach {
                assertTrue(
                    "${nameOf(fn)} records deviceName = ${it.groupValues[1]}",
                    allowed.matches(it.groupValues[1].trim())
                )
            }
            Regex("val peerName = ([^\n]+)").findAll(fn).forEach {
                assertTrue("${nameOf(fn)} names its peer through auditPeerName", it.groupValues[1].startsWith("auditPeerName("))
            }
        }
        assertTrue(
            "a backup peer is named through auditPeerName",
            "BackupAuditPeer(key, auditPeerName(key))" in source
        )
    }

    // -----------------------------------------------------------------
    // Key use records name the caller too: sign, decrypt, encrypt
    // -----------------------------------------------------------------

    @Test
    fun aSigningRecordNamesTheCallerNotTheLastPairedPeer() = runTest {
        handler.setConnectedDevicePublicKeyHex(USB_PEER)
        every { keystoreManager.generalKeyExists(KEY_ID) } returns true
        coEvery { keystoreManager.signWithAlgorithm(KEY_ID, any(), any()) } returns ByteArray(64)

        success(served(keyUse(MethodNames.LOCAL_SIGN, "data", "userVerificationRequired" to false, "algorithm" to "ES256"), peer = PEER))

        assertNamesCaller(single(AuditOperationType.SIGNING_REQUEST))
    }

    @Test
    fun anRsaDecryptionRecordNamesTheCallerNotTheLastPairedPeer() = runTest {
        handler.setConnectedDevicePublicKeyHex(USB_PEER)

        coEvery { keystoreManager.rsaDecrypt(KEY_ID, any()) } returns ByteArray(16)

        success(served(keyUse(MethodNames.LOCAL_DECRYPT, "ciphertext"), peer = PEER))

        assertNamesCaller(single(AuditOperationType.DECRYPTION_REQUEST))
    }

    @Test
    fun anEncryptionRecordNamesTheCallerNotTheLastPairedPeer() = runTest {
        handler.setConnectedDevicePublicKeyHex(USB_PEER)

        coEvery { keystoreManager.symmetricEncrypt(KEY_ID, any(), any()) } returns ByteArray(16)

        success(served(keyUse(MethodNames.LOCAL_SYMMETRIC_ENCRYPT, "plaintext"), peer = PEER))

        assertNamesCaller(single(AuditOperationType.ENCRYPTION_REQUEST))
    }

    @Test
    fun aSymmetricDecryptionRecordNamesTheCallerNotTheLastPairedPeer() = runTest {
        handler.setConnectedDevicePublicKeyHex(USB_PEER)

        coEvery { keystoreManager.symmetricDecrypt(KEY_ID, any(), any()) } returns ByteArray(16)

        success(served(keyUse(MethodNames.LOCAL_SYMMETRIC_DECRYPT, "ciphertext"), peer = PEER))

        assertNamesCaller(single(AuditOperationType.DECRYPTION_REQUEST))
    }

    /**
     * Every handler function that writes an audit record, and the share
     * gate, takes the peer from the request's own connection: none reads the
     * handler-wide peer, and every `deviceId` it records is the caller peer
     * ([RequestHandler]'s `currentPeerPublicKeyHex`, directly or through
     * `requireConfirmedPeer`). A new audit call that reads the global peer
     * fails here before it can record the wrong desktop.
     */
    @Test
    fun noAuditPathReadsTheHandlerWidePeer() {
        // Comments dropped, then one chunk per class member, so a KDoc or a
        // property never counts against its neighbour.
        val source = handlerSource()
            .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
            .replace(Regex("//[^\n]*"), "")
        val members = source.split(Regex(
            "\n(?=    (?:@\\w+\\s+)?(?:(?:private|internal|public|override|const|lateinit) )*" +
                "(?:suspend )?(?:fun|val|var|class|object) )"
        ))
        val memberFun = Regex("^\\s*(?:@\\w+\\s+)?(?:(?:private|internal|public|override) )*(?:suspend )?fun (\\w+)")
        fun nameOf(chunk: String) = memberFun.find(chunk)?.groupValues?.get(1)
        val functions = members.filter { nameOf(it) != null }
        val auditing = functions.filter { "AuditLogger.log" in it || nameOf(it) == "requireConfirmedPeer" }
        assertTrue("audit paths found: ${auditing.size}", auditing.size >= 8)
        val allowedPeers = setOf("callerPeer", "peerPublicKeyHex", "peer", "caller.peerPublicKeyHex", "null")
        val auditCaller = functions.single { nameOf(it) == "auditCaller" }
        assertTrue(
            "auditCaller takes the session's own peer",
            "val peer = attestingPeerPublicKeyHex()" in auditCaller
        )
        for (fn in auditing) {
            val name = nameOf(fn)
            assertFalse("$name reads the handler-wide peer", "connectedDevicePublicKeyHex" in fn)
            Regex("deviceId = ([\\w.]+)").findAll(fn).forEach {
                assertTrue("$name records deviceId = ${it.groupValues[1]}", it.groupValues[1] in allowedPeers)
            }
            if (Regex("deviceId = peerPublicKeyHex").containsMatchIn(fn)) {
                assertTrue(
                    "$name takes its peer from requireConfirmedPeer",
                    Regex("val peerPublicKeyHex = requireConfirmedPeer\\(").containsMatchIn(fn)
                )
            }
            if (Regex("deviceId = peer\\b").containsMatchIn(fn)) {
                assertTrue(
                    "$name takes its peer from backupAuditPeer",
                    "val peer = backupAuditPeer()" in fn
                )
            }
            if (Regex("deviceId = callerPeer\\b").containsMatchIn(fn)) {
                assertTrue(
                    "$name takes its peer from currentPeerPublicKeyHex",
                    "val callerPeer = currentPeerPublicKeyHex()" in fn
                )
            }
        }
        // Beyond the audit paths: no sharing decision reads it either. Only
        // its own setters and getter, the attestation policy's no-session
        // fallback, and the one peer resolver may touch the handler-wide peer.
        val readers = functions
            .filter { "connectedDevicePublicKeyHex" in it }
            .mapNotNull { nameOf(it) }
            .toSet()
        assertEquals(
            setOf(
                "setSessionId",
                "setConnectedDevicePublicKeyHex",
                "clearConnectedDevicePublicKeyHex",
                "getConnectedDevicePublicKeyHex",
                "attestingPeerPublicKeyHex",
                "currentPeerPublicKeyHex"
            ),
            readers
        )
        val gate = auditing.single { nameOf(it) == "requireConfirmedPeer" }
        assertTrue("requireConfirmedPeer uses the one resolver", "currentPeerPublicKeyHex()" in gate)
        assertFalse("the old caller-only resolver is gone", functions.any { nameOf(it) == "callerPeerPublicKeyHex" })
        val choke = functions.single { nameOf(it) == "currentPeerPublicKeyHex" }
        assertTrue("the choke point reads the CallerSession first", "[CallerSession] ?: return connectedDevicePublicKeyHex" in choke)
    }

    // -----------------------------------------------------------------
    // A credential and a general key sharing an id (#255 review r2)
    // -----------------------------------------------------------------

    /**
     * #255 review r2: with the credential's delete still owed beside the
     * general key's surviving row, local.getPublicKey and
     * local.importSharedKey of the id export the general key's own public
     * key, never the deleted credential's under the general key's grant;
     * with no general key under the id, the lookup would reach the
     * credential, and both are refused. A real [KeystoreManager] resolves.
     */
    @Test
    fun aPendingCredentialDeleteNeverExportsTheCredentialAsTheGeneralKey() = runTest {
        val aliases = HashMap<String, ByteArray>()
        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } answers { firstArg<String>() in aliases }
        every { platform.getCertificate(any()) } answers {
            aliases[firstArg()]?.let { bytes ->
                mockk<java.security.cert.Certificate> {
                    every { publicKey } returns mockk { every { encoded } returns bytes }
                }
            }
        }
        every { KeyStore.getInstance("AndroidKeyStore") } returns platform
        val credentialKey = "credential".toByteArray()
        val generalKey = "general".toByteArray()
        aliases["xkey_credential_$KEY_ID"] = credentialKey
        aliases["xkey_key_$KEY_ID"] = generalKey
        // The credential's delete is owed beside the general key's row 7.
        coEvery { policies.keyInstance(KEY_ID) } returns 7L
        coEvery { policies.deletion(KEY_ID) } returns com.automatethethings.xkey.storage.entity.KeyDeletionEntity(
            KEY_ID, 7L, "keystore",
            JSONObject().put("${KeystoreManager.KEYSTORE_ENTRY}xkey_credential_$KEY_ID", "1").toString()
        )
        coEvery { keyDao.getByKeyId(KEY_ID) } returns keyEntity(SharingPolicyType.ALL_PEERS, keyType = "signing")
        handler = RequestHandler(
            context = context,
            keystoreManager = KeystoreManager(context),
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices
        )
        handler.setConnectedDevicePublicKeyHex(PEER)
        val getPublicKey = Request(
            id = 5,
            method = MethodNames.LOCAL_GET_PUBLIC_KEY,
            params = JSONObject().put("keyId", KEY_ID).put("format", "der")
        ).toJson()

        assertEquals(
            "getPublicKey exports the general key's own key",
            Base64.getEncoder().encodeToString(generalKey),
            success(served(getPublicKey)).getString("publicKey")
        )
        val pem = success(served(importSharedKey())).getString("public_key_pem")
        assertTrue("importSharedKey exports the general key's own key: $pem", Base64.getEncoder().encodeToString(generalKey) in pem)
        assertFalse(Base64.getEncoder().encodeToString(credentialKey) in pem)

        // No general key under the id: the general lookup finds none, and
        // never reads the credential (#255 review r3).
        aliases.remove("xkey_key_$KEY_ID")
        for (request in listOf(getPublicKey, importSharedKey())) {
            val response = Response.fromJson(served(request))
            assertTrue("refused: $response", response.error != null && response.result == null)
        }
    }

    /** A platform Keystore holding [keys] by alias, read by a real [KeystoreManager]. */
    private fun platformKeystore(keys: Map<String, java.security.KeyPair>) {
        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } answers { firstArg<String>() in keys }
        every { platform.getKey(any(), any()) } answers { keys[firstArg()]?.private }
        every { platform.getCertificate(any()) } answers {
            keys[firstArg()]?.let { pair -> mockk<java.security.cert.Certificate> { every { publicKey } returns pair.public } }
        }
        every { KeyStore.getInstance("AndroidKeyStore") } returns platform
    }

    private fun ecKeyPair(): java.security.KeyPair =
        java.security.KeyPairGenerator.getInstance("EC").apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    /**
     * #255 review r3: local.generateKey of an id a credential already holds
     * is refused before any key is made, so no general key is ever created
     * beside a credential of its id.
     */
    @Test
    fun aKeyIsNeverGeneratedUnderAnIdACredentialHolds() = runTest {
        platformKeystore(mapOf("xkey_credential_$KEY_ID" to ecKeyPair()))
        val keystore = io.mockk.spyk(KeystoreManager(context))
        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices
        )
        handler.setConnectedDevicePublicKeyHex(PEER)
        val generate = Request(
            id = 6,
            method = MethodNames.LOCAL_GENERATE_KEY,
            params = JSONObject().put("keyId", KEY_ID).put("keyType", "fido2").put("algorithm", "ES256")
                .put("rpId", "example.com").put("requireUserVerification", false)
        ).toJson()

        val response = Response.fromJson(served(generate))

        assertEquals("refused: $response", ErrorCodes.KEY_EXISTS, response.error?.code)
        io.mockk.coVerify(exactly = 0) { keystore.generateKeyForAlgorithm(any(), any(), any(), any()) }
        io.mockk.coVerify(exactly = 0) { keystore.generateKeyWithAuthDuration(any(), any(), any()) }
    }

    /**
     * #255 verify r6: local.generateKey with an empty keyId wrote a software
     * key whose record names no id, which the reader then took as any id's.
     * The id is refused as invalid params before any key is made or written.
     */
    @Test
    fun anEmptyKeyIdIsRefusedBeforeAnyKeyIsWritten() = runTest {
        handler.setConnectedDevicePublicKeyHex(PEER)
        val generate = Request(
            id = 7,
            method = MethodNames.LOCAL_GENERATE_KEY,
            params = JSONObject().put("keyId", "").put("algorithm", "AES-256")
                .put("exportable", true).put("requireUserVerification", false)
        ).toJson()

        val response = Response.fromJson(served(generate))

        assertEquals("refused: $response", ErrorCodes.INVALID_PARAMS, response.error?.code)
        io.mockk.verify(exactly = 0) { anyConstructed<SoftwareKeyStore>().put(any()) }
        io.mockk.coVerify(exactly = 0) { keystoreManager.generateKeyForAlgorithm(any(), any(), any(), any()) }
        assertEquals("files written for an empty id", emptyList<String>(), java.io.File(tmp.root, "software_keys").list()?.toList().orEmpty())
    }

    /**
     * #255 review r3: a passkey assertion signs with the key whose COSE key
     * the passkey's creation returned. With a general key and a credential
     * both under the id the assertion is refused, never signed with the
     * other key; with the general key alone (a passkey made through
     * local.generateKey) the signature verifies against the general key's
     * public key, the one its COSE key encodes, and not the credential's.
     */
    @Test
    fun aPasskeyAssertionSignsWithTheKeyWhosePublicKeyWasReturned() = runTest {
        val general = ecKeyPair()
        val credential = ecKeyPair()
        val keys = mutableMapOf("xkey_key_$KEY_ID" to general, "xkey_credential_$KEY_ID" to credential)
        platformKeystore(keys)
        val keystore = KeystoreManager(context)
        coEvery { keyDao.getByKeyId(KEY_ID) } returns
            keyEntity(SharingPolicyType.ALL_PEERS, shareable = true, keyType = "fido2")
        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices
        )
        handler.setConnectedDevicePublicKeyHex(PEER)
        val clientDataHash = java.security.MessageDigest.getInstance("SHA-256").digest("client-data".toByteArray())
        val assertion = Request(
            id = 7,
            method = MethodNames.LOCAL_SIGN_FIDO2_ASSERTION,
            params = JSONObject().put("credentialId", KEY_ID).put("rpId", "example.com")
                .put("clientDataHash", Base64.getEncoder().encodeToString(clientDataHash))
                .put("userVerificationRequired", false)
        ).toJson()

        // Both namespaces hold the id: no key is the passkey's for certain.
        assertEquals(null, keystore.soleKind(KEY_ID))
        val refused = Response.fromJson(served(assertion))
        assertEquals("refused: $refused", ErrorCodes.KEY_NOT_FOUND, refused.error?.code)

        // The general key alone: its COSE key is the one generateKey returned.
        keys.remove("xkey_credential_$KEY_ID")
        val cose = keystore.getCOSEPublicKey(KEY_ID, com.automatethethings.xkey.crypto.UserKeyKind.GENERAL)
        fun coordinate(key: java.security.PublicKey) = (key as java.security.interfaces.ECPublicKey).w.affineX.toByteArray().takeLast(32).toByteArray()
        assertTrue("the COSE key encodes the general key", cose != null && java.util.Collections.indexOfSubList(cose.toList(), coordinate(general.public).toList()) >= 0)
        assertFalse("the COSE key encodes the credential", java.util.Collections.indexOfSubList(cose!!.toList(), coordinate(credential.public).toList()) >= 0)
        val result = success(served(assertion))
        val authData = Base64.getDecoder().decode(result.getString("authenticatorData"))
        val signature = Base64.getDecoder().decode(result.getString("signature"))
        val dataHash = java.security.MessageDigest.getInstance("SHA-256").digest(authData + clientDataHash)
        fun verifies(key: java.security.PublicKey) = java.security.Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(dataHash)
            verify(signature)
        }
        assertTrue("the assertion verifies against the returned public key", verifies(general.public))
        assertFalse("the assertion signed with the credential", verifies(credential.public))
    }

    /**
     * #255 review r4: a hardware key shares its public key from either
     * namespace (SPEC key sharing). A key that lives only under its
     * credential alias exports its own public key through local.getPublicKey
     * and shares it through local.importSharedKey, never KEY_NOT_FOUND.
     */
    @Test
    fun aCredentialOnlyKeySharesAndExportsItsPublicKey() = runTest {
        val credential = ecKeyPair()
        platformKeystore(mapOf("xkey_credential_$KEY_ID" to credential))
        coEvery { keyDao.getByKeyId(KEY_ID) } returns keyEntity(SharingPolicyType.ALL_PEERS, keyType = "signing")
        handler = RequestHandler(
            context = context,
            keystoreManager = KeystoreManager(context),
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices
        )
        handler.setConnectedDevicePublicKeyHex(PEER)
        val expected = Base64.getEncoder().encodeToString(credential.public.encoded)
        val getPublicKey = Request(
            id = 8,
            method = MethodNames.LOCAL_GET_PUBLIC_KEY,
            params = JSONObject().put("keyId", KEY_ID).put("format", "der")
        ).toJson()

        assertEquals("getPublicKey exports the credential's key", expected, success(served(getPublicKey)).getString("publicKey"))
        val pem = success(served(importSharedKey())).getString("public_key_pem")
        assertTrue("importSharedKey shares the credential's key: $pem", expected in pem.replace("\n", "").replace("\r", ""))
    }

    /**
     * #270 review r4: a credential row beside a general key of the same id
     * exports the key its row describes ([KeystoreManager.rowKeyKind]), the
     * credential's, under the row's algorithm, never the general key's.
     */
    @Test
    fun aCredentialRowBesideASameIdGeneralKeyExportsTheCredentialsKey() = runTest {
        val credential = ecKeyPair()
        val general = ecKeyPair()
        platformKeystore(mapOf("xkey_credential_$KEY_ID" to credential, "xkey_key_$KEY_ID" to general))
        coEvery { keyDao.getByKeyId(KEY_ID) } returns keyEntity(SharingPolicyType.ALL_PEERS, keyType = "fido2")
            .copy(algorithm = "ES256", publicKeyDer = credential.public.encoded)
        handler = RequestHandler(
            context = context,
            keystoreManager = KeystoreManager(context),
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices
        )
        handler.setConnectedDevicePublicKeyHex(PEER)
        val getPublicKey = Request(
            id = 8,
            method = MethodNames.LOCAL_GET_PUBLIC_KEY,
            params = JSONObject().put("keyId", KEY_ID).put("format", "der")
        ).toJson()

        val result = success(served(getPublicKey))
        assertEquals(
            "getPublicKey exports the credential's key",
            Base64.getEncoder().encodeToString(credential.public.encoded),
            result.getString("publicKey")
        )
        assertEquals("ES256", result.getString("algorithm"))
    }

    /**
     * #255 review r5: with the Ed25519 store unreadable, whether a legacy
     * general Ed25519 key holds the id is unknown, so a credential of that
     * id is never exported in its place: local.getPublicKey and
     * local.importSharedKey refuse and export nothing, never fall back to
     * the credential namespace. The same id exports once the store reads.
     */
    @Test
    fun anUnreadableEd25519StoreExportsNeitherNamespace() = runTest {
        val credential = ecKeyPair()
        platformKeystore(mapOf("xkey_credential_$KEY_ID" to credential))
        coEvery { keyDao.getByKeyId(KEY_ID) } returns keyEntity(SharingPolicyType.ALL_PEERS, keyType = "signing")
        val keystore = io.mockk.spyk(KeystoreManager(context))
        every { keystore.ed25519Prefs() } throws java.security.GeneralSecurityException("master key unavailable")
        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices
        )
        handler.setConnectedDevicePublicKeyHex(PEER)
        val getPublicKey = Request(
            id = 8,
            method = MethodNames.LOCAL_GET_PUBLIC_KEY,
            params = JSONObject().put("keyId", KEY_ID).put("format", "der")
        ).toJson()
        val encoded = Base64.getEncoder().encodeToString(credential.public.encoded)

        for ((name, request) in listOf("getPublicKey" to getPublicKey, "importSharedKey" to importSharedKey())) {
            val bytes = served(request)
            val response = Response.fromJson(bytes)
            assertNull("$name exported with an unreadable store: ${response.result}", response.result)
            assertTrue("$name answered no error", response.error != null)
            assertFalse("$name sent the credential's key", encoded in String(bytes))
        }
        verify(exactly = 0) { keystore.getPublicKeyPEM(any(), any()) }
        verify(exactly = 0) { keystore.getPublicKeyDER(any(), any()) }
        assertTrue(
            "a refused export was recorded as a success",
            entries.none { it.operationType == AuditOperationType.KEY_EXPORTED && it.success }
        )

        // The store reads again: the credential-only id exports its own key.
        every { keystore.ed25519Prefs() } returns null
        assertEquals(encoded, success(served(getPublicKey)).getString("publicKey"))
    }

    /**
     * #255 review r7, the handler side of the bypass check: a request whose
     * key read meets an unreadable key store (here the software key store)
     * is answered with a refusal, operation denied, never an internal error
     * and never an exception out of the handler.
     */
    @Test
    fun anUnreadableKeyStoreIsARefusedRequest() = runTest {
        platformKeystore(mapOf("xkey_credential_$KEY_ID" to ecKeyPair()))
        coEvery { keyDao.getByKeyId(KEY_ID) } returns keyEntity(SharingPolicyType.ALL_PEERS, keyType = "signing")
        val keystore = realKeystoreHandler()
        val software = io.mockk.mockk<com.automatethethings.xkey.crypto.SoftwareKeyStore>()
        every { software.presence(any()) } returns com.automatethethings.xkey.crypto.KeyPresence.UNREADABLE
        every { keystore.softwareKeys() } returns software
        val getPublicKey = Request(
            id = 11,
            method = MethodNames.LOCAL_GET_PUBLIC_KEY,
            params = JSONObject().put("keyId", KEY_ID).put("format", "der")
        ).toJson()

        val response = Response.fromJson(served(getPublicKey))

        assertNull("a key was read from an unreadable store: ${response.result}", response.result)
        assertEquals("the request is refused: ${response.error}", ErrorCodes.OPERATION_DENIED, response.error?.code)
    }

    /**
     * #255 verify r2y: an older build's software key record whose metadata
     * cannot be parsed while its material is there could be this id's, so
     * the store is unreadable for it: local.importSharedKey refuses and never
     * falls back to the credential under the id.
     */
    @Test
    fun aMalformedLegacySoftwareRecordRefusesTheShareOfACredential() = runTest {
        val credential = ecKeyPair()
        platformKeystore(mapOf("xkey_credential_$KEY_ID" to credential))
        coEvery { keyDao.getByKeyId(KEY_ID) } returns keyEntity(SharingPolicyType.ALL_PEERS, keyType = "signing")
        val keystore = realKeystoreHandler()
        val filesDir = java.nio.file.Files.createTempDirectory("software-keys").toFile()
        try {
            val dir = java.io.File(filesDir, "software_keys").apply { mkdirs() }
            java.io.File(dir, "legacy.meta").writeText("{not json")
            java.io.File(dir, "legacy.key").writeBytes(ByteArray(4))
            val storeContext = io.mockk.mockk<android.content.Context>()
            every { storeContext.filesDir } returns filesDir
            val software = com.automatethethings.xkey.crypto.SoftwareKeyStore(storeContext, io.mockk.mockk(relaxed = true))
            every { keystore.softwareKeys() } returns software

            val bytes = served(importSharedKey())
            val response = Response.fromJson(bytes)

            assertNull("importSharedKey shared past a malformed record: ${response.result}", response.result)
            assertEquals("the request is refused: ${response.error}", ErrorCodes.OPERATION_DENIED, response.error?.code)
            val encoded = Base64.getEncoder().encodeToString(credential.public.encoded)
            assertFalse("importSharedKey sent the credential's key", encoded in String(bytes))
        } finally {
            filesDir.deleteRecursively()
        }
    }

    /** A handler over a spied real [KeystoreManager] on the platform keystore, the Ed25519 store empty. */
    private fun realKeystoreHandler(): KeystoreManager {
        val keystore = io.mockk.spyk(KeystoreManager(context))
        every { keystore.ed25519Prefs() } returns null
        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices
        )
        handler.setConnectedDevicePublicKeyHex(PEER)
        return keystore
    }

    /**
     * #255 review r6: a software key (SoftwareKeyStore) and a credential
     * under one id. The general namespace counts the software store, so the
     * id exports as its general key: local.importSharedKey shares the
     * software key's material, local.getPublicKey (no Keystore public key in
     * the general namespace) refuses, and neither ever sends the
     * credential's public key under the software key's row.
     */
    @Test
    fun aSoftwareKeyBesideACredentialNeverExportsTheCredential() = runTest {
        val credential = ecKeyPair()
        platformKeystore(mapOf("xkey_credential_$KEY_ID" to credential))
        givenSoftwareKey(exportable = true, shareable = true)
        every { anyConstructed<SoftwareKeyStore>().presence(KEY_ID) } returns
            com.automatethethings.xkey.crypto.KeyPresence.PRESENT
        val keystore = realKeystoreHandler()
        val encoded = Base64.getEncoder().encodeToString(credential.public.encoded)

        assertEquals(com.automatethethings.xkey.crypto.UserKeyKind.GENERAL, keystore.exportKind(KEY_ID))
        assertNull("an id two keys hold has no sole kind", keystore.soleKind(KEY_ID))

        val getPublicKey = Request(
            id = 11,
            method = MethodNames.LOCAL_GET_PUBLIC_KEY,
            params = JSONObject().put("keyId", KEY_ID).put("format", "der")
        ).toJson()
        val refused = served(getPublicKey)
        val response = Response.fromJson(refused)
        assertNull("getPublicKey exported a key: ${response.result}", response.result)
        assertEquals(ErrorCodes.EXPORT_FAILED, response.error?.code)
        assertFalse("getPublicKey sent the credential's key", encoded in String(refused))

        val shared = served(importSharedKey())
        val result = success(shared)
        assertEquals(Base64.getEncoder().encodeToString(MATERIAL), result.getString("wrapped_key"))
        assertFalse("importSharedKey sent the credential's key", encoded in String(shared))

        val credentialKind = com.automatethethings.xkey.crypto.UserKeyKind.CREDENTIAL
        verify(exactly = 0) { keystore.getPublicKeyPEM(KEY_ID, credentialKind) }
        verify(exactly = 0) { keystore.getPublicKeyDER(KEY_ID, credentialKind) }
    }

    /**
     * #255 review r6: both generators refuse an id a software key holds,
     * before any key is made, so no credential or Keystore general key is
     * ever created beside it.
     */
    @Test
    fun noGeneratorCreatesAKeyUnderAnIdASoftwareKeyHolds() = runTest {
        platformKeystore(emptyMap())
        every { anyConstructed<SoftwareKeyStore>().presence(KEY_ID) } returns
            com.automatethethings.xkey.crypto.KeyPresence.PRESENT
        val keystore = realKeystoreHandler()
        val legacy = Request(
            id = 12,
            method = MethodNames.GENERATE_KEY,
            params = JSONObject().put("credentialId", KEY_ID).put("algorithm", -7).put("requireUserVerification", false)
        ).toJson()
        val local = Request(
            id = 13,
            method = MethodNames.LOCAL_GENERATE_KEY,
            params = JSONObject().put("keyId", KEY_ID).put("keyType", "signing").put("algorithm", "ES256")
                .put("requireUserVerification", false)
        ).toJson()

        val legacyResponse = Response.fromJson(served(legacy))
        val localResponse = Response.fromJson(served(local))

        assertEquals("legacy generateKey: $legacyResponse", ErrorCodes.INVALID_PARAMS, legacyResponse.error?.code)
        assertEquals("local.generateKey: $localResponse", ErrorCodes.KEY_EXISTS, localResponse.error?.code)
        io.mockk.coVerify(exactly = 0) { keystore.generateKey(any(), any(), any()) }
        io.mockk.coVerify(exactly = 0) { keystore.generateKeyWithAuthDuration(any(), any(), any()) }
        io.mockk.coVerify(exactly = 0) { keystore.generateKeyForAlgorithm(any(), any(), any(), any()) }
        verify(exactly = 0) { anyConstructed<SoftwareKeyStore>().put(any()) }
    }

    /**
     * #255 review r4: generateKey and local.generateKey of one id at once,
     * the first holding its creation open, make exactly one key: the second
     * is refused, never run beside the first (the two RPC families reserve
     * the id under one name, and check it inside the shared material lock).
     */
    @Test
    fun concurrentGeneratorsOfOneIdMakeOneKey() = runTest {
        val keys = java.util.concurrent.ConcurrentHashMap<String, java.security.KeyPair>()
        platformKeystore(keys)
        val keystore = io.mockk.spyk(KeystoreManager(context))
        val release = kotlinx.coroutines.CompletableDeferred<Unit>()
        val generated = java.util.concurrent.atomic.AtomicInteger()
        coEvery { keystore.generateKeyWithAuthDuration(KEY_ID, any(), any()) } coAnswers {
            release.await()
            generated.incrementAndGet()
            keys["xkey_credential_$KEY_ID"] = ecKeyPair()
            keystore.getCOSEPublicKey(KEY_ID, com.automatethethings.xkey.crypto.UserKeyKind.CREDENTIAL)!!
        }
        coEvery { keystore.generateKeyForAlgorithm(KEY_ID, any(), any(), any()) } coAnswers {
            release.await()
            generated.incrementAndGet()
            val pair = ecKeyPair()
            keys["xkey_key_$KEY_ID"] = pair
            pair.public.encoded
        }
        every { keystore.credentialSecurityLevel(KEY_ID) } returns com.automatethethings.xkey.crypto.KeySecurityLevel.TEE
        every { keystore.generalKeySecurityLevel(KEY_ID) } returns com.automatethethings.xkey.crypto.KeySecurityLevel.TEE
        // The store on in-memory tables: a relaxed database's transaction never ends.
        val tables = com.automatethethings.xkey.storage.FakeKeyPolicyTables()
        mockkObject(com.automatethethings.xkey.storage.KeyPolicyStore.Companion)
        every { com.automatethethings.xkey.storage.KeyPolicyStore.of(any(), any()) } returns
            tables.store(com.automatethethings.xkey.storage.KeyPolicyStore.KeyResolver { id, kind -> keystore.resolveKey(id, kind) })
        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices
        )
        handler.setConnectedDevicePublicKeyHex(PEER)
        val legacy = Request(
            id = 9,
            method = MethodNames.GENERATE_KEY,
            params = JSONObject().put("credentialId", KEY_ID).put("algorithm", -7).put("requireUserVerification", false)
        ).toJson()
        val local = Request(
            id = 10,
            method = MethodNames.LOCAL_GENERATE_KEY,
            params = JSONObject().put("keyId", KEY_ID).put("keyType", "signing").put("algorithm", "ES256")
                .put("requireUserVerification", false)
        ).toJson()

        for (order in listOf(listOf(legacy, local), listOf(local, legacy))) {
            keys.clear()
            generated.set(0)
            // Two connections, as two peers' requests arrive.
            val first = backgroundScope.async { Response.fromJson(served(order[0], connection = "test:first")) }
            kotlinx.coroutines.yield()
            val second = Response.fromJson(
                kotlinx.coroutines.withTimeout(10_000) { served(order[1], connection = "test:second") }
            )
            assertTrue("the second creation is refused while the first runs: $second", second.error != null && second.result == null)
            if (!release.isCompleted) release.complete(Unit)
            val made = first.await()
            assertTrue("the first creation makes its key: $made", made.error == null)
            assertEquals("exactly one key under the id", 1, generated.get())
            assertEquals("exactly one namespace holds the id", 1, keys.size)
        }
    }

    /**
     * #255 review r3, the bypass check: no caller resolves a key id without
     * naming its namespace. KeystoreManager has no resolver, lookup, sign,
     * exists or delete of a key id without a non-null kind, and each derives
     * its alias from that kind alone; every sign of a user key in Handler and
     * the credential provider runs inside the use gate of the key id and kind
     * it signs with; the gate resolves through the same resolver. Any
     * unqualified resolver (a nullable or defaulted kind, a one-argument
     * resolve) fails this test.
     */
    @Test
    fun everyKeyLookupInHandlerResolvesTheKindItsGateChecks() {
        val source = handlerSource()
        val lookups = Regex("keystoreManager\\.(getPublicKeyDER|getPublicKeyPEM|getPublicKeySSH|getCOSEPublicKey|getPublicKey|getAttestationChain|keySecurityLevel|resolveKeystoreAlias|resolveKey|keyExists|deleteKey|isKeyStrongBoxBacked)\\(([^)]*)\\)")
            .findAll(source).toList()
        // A generated key's discard deletes its own alias (#255 review r7), no lookup.
        assertTrue("lookups found: ${lookups.size}", lookups.size >= 8)
        for (lookup in lookups) {
            assertTrue(
                "a lookup names the user key it reads: ${lookup.value}",
                Regex(",\\s*(com\\.automatethethings\\.xkey\\.crypto\\.UserKeyKind\\.(GENERAL|CREDENTIAL)|[a-z]\\w*Kind)$").containsMatchIn(lookup.groupValues[2])
            )
        }
        for (raw in listOf("xkey_credential_", "xkey_key_", "KEY_ALIAS_PREFIX", "keyStore.", "containsAlias(")) {
            assertFalse("Handler reads a Keystore alias itself: $raw", raw in source.lines().filterNot { it.trim().startsWith("//") || it.trim().startsWith("*") }.joinToString("\n"))
        }
        assertTrue("Handler's store gates through the Keystore resolver", "KeyPolicyStore.of(XKeyDatabase.getInstance(context), keystoreManager)" in source)

        val main = listOf(java.io.File("src/main/kotlin"), java.io.File("app/src/main/kotlin")).first { it.isDirectory }
        val manager = java.io.File(main, "com/automatethethings/xkey/crypto/KeystoreManager.kt").readText()
        Regex("\\w+\\s*:\\s*UserKeyKind\\?").findAll(manager).forEach {
            org.junit.Assert.fail("KeystoreManager takes a nullable kind, an unqualified resolver: ${it.value}")
        }
        assertTrue(
            "resolveKeystoreAlias is the resolver's alias",
            "fun resolveKeystoreAlias(keyId: String, kind: UserKeyKind): String? = resolveKey(keyId, kind)?.alias" in manager
        )
        assertTrue(
            "resolveKey names its namespace, its presence from every backend of it (#255 review r6)",
            "fun resolveKey(keyId: String, kind: UserKeyKind): ResolvedKey? {\n" +
                "        if (!holdsUserKey(keyId, kind)) return null\n" +
                "        val own = userKeyAlias(keyId, kind)" in manager
        )
        assertEquals("one resolveKey", 1, Regex("fun resolveKey\\(").findAll(manager).count())
        assertEquals("one resolveKeystoreAlias", 1, Regex("fun resolveKeystoreAlias\\(").findAll(manager).count())
        for (fn in listOf(
            "getPublicKeyDER", "getPublicKeySSH", "getPublicKey", "getCOSEPublicKey", "getAttestationChain", "keySecurityLevel",
            "sign", "signWithoutBiometric", "keyExists", "deleteKey", "isKeyStrongBoxBacked"
        )) {
            val starts = Regex("fun $fn\\(").findAll(manager).map { it.range.first }.toList()
            assertEquals("one $fn", 1, starts.size)
            val start = starts.single()
            val header = manager.substring(start, manager.indexOf(")", manager.indexOf("kind", start)) + 1)
            assertTrue("$fn takes a non-null kind: $header", Regex("\\bkind: UserKeyKind[,)\\s]").containsMatchIn(header + " "))
            val body = manager.substring(start, manager.indexOf("\n\n", start).let { if (it < 0) manager.length else it })
            // A delete deletes the alias of its kind directly, past no cross-backend presence guard (#255 review r7).
            val resolves = if (fn == "deleteKey") "userKeyAlias\\(\\w+, kind\\)" else "(resolveKeystoreAlias|keySecurityLevel)\\(\\w+, kind\\)"
            assertTrue("$fn resolves with its kind", Regex(resolves).containsMatchIn(body))
        }
        val pem = manager.substring(manager.indexOf("fun getPublicKeyPEM("))
        assertTrue("getPublicKeyPEM reads the DER of its kind", Regex("getPublicKeyDER\\(\\w+, kind\\)").containsMatchIn(pem.substring(0, pem.indexOf("\n    }\n"))))

        // No caller anywhere resolves a key id without a namespace.
        main.walkTopDown().filter { it.extension == "kt" }.forEach { file ->
            val text = file.readText()
            Regex("\\bresolve(KeystoreAlias|Key)\\(\\s*[\\w.]+\\s*\\)").findAll(text).forEach {
                org.junit.Assert.fail("${file.name}: an unqualified resolver call: ${it.value}")
            }
        }

        // Each user-key sign runs inside the gate of the id and kind it signs with.
        val credentialProvider = java.io.File(main, "com/automatethethings/xkey/credential/handler/GetCredentialHandler.kt").readText()
        for ((name, text) in listOf("Handler" to source, "GetCredentialHandler" to credentialProvider)) {
            val calls = Regex("keystoreManager\\.(sign|signWithoutBiometric)\\(").findAll(text).count()
            val gated = Regex("withUsableKey\\(([\\w.]+), (\\w+)\\) \\{\\s*keystoreManager\\.(sign|signWithoutBiometric)\\(\\s*(credentialId = )?([\\w.]+),\\s*(kind = )?(\\w+)")
                .findAll(text).toList()
            assertTrue("$name signs a user key", calls > 0)
            assertEquals("$name: every sign runs in its gate", calls, gated.size)
            for (call in gated) {
                assertEquals("$name signs the id it gates: ${call.value}", call.groupValues[1], call.groupValues[5])
                assertEquals("$name signs with the kind it gates: ${call.value}", call.groupValues[2], call.groupValues[7])
            }
        }

        // #255 review r4: the share and export paths resolve the key's kind
        // once and gate and read that kind, never a hardcoded namespace.
        val sheet = java.io.File(main, "com/automatethethings/xkey/ui/KeySharingBottomSheet.kt").readText()
        assertTrue("the desktop share reads through the one share read", "keyPolicyStore.readShareable(" in sheet)
        assertFalse("the desktop share reads no key itself", Regex("getPublicKey\\w*\\(").containsMatchIn(sheet))
        assertTrue("importSharedKey reads through the one share read", "keyPolicyStore.readShareable(keyId, keystoreManager)" in source)
        assertTrue("getPublicKey gates the kind it exports", "keyPolicyStore.withUsableKey(pubKeyParams.keyId, exportKind)" in source)
        val share = java.io.File(main, "com/automatethethings/xkey/storage/ShareableKeyRead.kt").readText()
        assertTrue("the share read resolves its kind once", "val kind = keystore.exportKind(keyId)" in share && "withUsableKey(keyId, kind)" in share)

        val store = java.io.File(main, "com/automatethethings/xkey/storage/KeyPolicyStore.kt").readText()
        assertTrue("the gate resolves as the lookups do", "keys = KeyResolver { keyId, kind -> keystore.resolveKey(keyId, kind) }" in store)
        assertTrue("requireUsable checks the key the lookup reaches", "keys.resolve(keyId, kind)" in store)
        main.walkTopDown().filter { it.extension == "kt" }.forEach { file ->
            Regex("KeyPolicyStore\\.of\\(([^\\n]*)\\)").findAll(file.readText()).forEach { call ->
                assertTrue("${file.name}: every store resolves through the Keystore: ${call.value}", "," in call.groupValues[1])
            }
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun handlerSource(): String {
        val rel = "src/main/kotlin/com/automatethethings/xkey/protocol/Handler.kt"
        val file = listOf(java.io.File(rel), java.io.File("app/$rel")).first { it.isFile }
        return file.readText()
    }

    private fun keyUse(method: String, payloadField: String, vararg extra: Pair<String, Any>): ByteArray =
        Request(
            id = 4,
            method = method,
            params = JSONObject()
                .put("keyId", KEY_ID)
                .put(payloadField, Base64.getEncoder().encodeToString("payload".toByteArray()))
                .apply { extra.forEach { (k, v) -> put(k, v) } }
        ).toJson()

    private fun assertNamesCaller(entry: AuditLogEntity) {
        assertEquals("entry names the caller: $entry", PEER, entry.deviceId)
        assertEquals("entry names the caller: $entry", PEER_NAME, entry.deviceName)
    }

    /** Handles [request] as one arriving on a served connection whose peer is [peer]. */
    private suspend fun served(request: ByteArray, peer: String? = PEER, connection: String = "test:connection"): ByteArray =
        withContext(RequestHandler.servedConnection(SessionBindingProvider { null }, peer, connection)) {
            handler.handleRawRequest(request)
        }

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
        shareable: Boolean = false,
        keyType: String = "symmetric"
    ) = KeyEntity(
        keyId = KEY_ID,
        keyType = keyType,
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
        const val USB_PEER = "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22"
        const val USB_PEER_NAME = "Laptop"
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
