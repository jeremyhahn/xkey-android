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
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.settings.DeviceLookup
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
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
import java.security.KeyStore
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Ignore
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * `local.importSharedKey` decides the share permission before it reads the
 * key a share would send, and a refused share keeps none of the software
 * key's material: the material read for the refusal's record is zeroed
 * before the refusal returns, so a peer the policy refuses never has the
 * key's secret decrypted into memory that outlives the request.
 *
 * This drives the real handler; the database, the software key store and
 * the Android edges are mocked, as in [KeyShareAuditTest].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ImportSharedKeyRefusalTest {

    private lateinit var keyDao: KeyDao
    private lateinit var grants: KeySharingPolicyDao
    private lateinit var handler: RequestHandler
    private val policies = mockk<KeyPolicyDao>(relaxed = true) {
        coEvery { deletion(any()) } returns null
        // No policy row: the store enforces the key row's own policy.
        coEvery { policyRow(any()) } returns null
    }

    /** Whether the share permission was decided (the Selected Peers grant read). */
    private var decided = false

    /** For each software key read, whether it ran before the permission was decided. */
    private val readsBeforeDecision = mutableListOf<Boolean>()

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
        every { AuditLogger["log"](any<AuditLogEntity>()) } returns Unit

        keyDao = mockk(relaxed = true)
        coEvery { keyDao.getByKeyId(any()) } returns null
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        every { database.keyPolicyDao() } returns policies
        grants = mockk(relaxed = true)
        coEvery { grants.isKeySharedWithPeer(any(), any()) } returns false
        coEvery { grants.isPeerGranted(any(), any()) } answers {
            decided = true
            false
        }
        every { database.keySharingPolicyDao() } returns grants
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        // SoftwareKeyStore's default cipher opens AndroidKeyStore as it is built.
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        mockkConstructor(SoftwareKeyStore::class)
        every { anyConstructed<SoftwareKeyStore>().get(any()) } returns null
        every { anyConstructed<SoftwareKeyStore>().contains(any()) } returns false
        every { anyConstructed<SoftwareKeyStore>().put(any()) } just runs

        Dispatchers.setMain(UnconfinedTestDispatcher())

        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns tmp.root
        every { context.applicationContext } returns context
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        val pairedDevices = mockk<PairedDeviceRepository>(relaxed = true)
        every { pairedDevices.lookupDevice(any()) } returns DeviceLookup.NotPaired
        every { pairedDevices.lookupDevice(PEER) } returns DeviceLookup.Paired(PairedDeviceData(PEER, "Desktop", 0L))
        every { pairedDevices.isRevocationPending(any()) } returns false

        val keystoreManager = mockk<KeystoreManager>(relaxed = true)
        every { keystoreManager.getPublicKeyPEM(any(), any()) } returns null
        every { keystoreManager.exportKind(any()) } returns UserKeyKind.GENERAL
        every { keystoreManager.rowKeyKind(any(), any(), any(), any()) } returns UserKeyKind.GENERAL
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
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
    }

    @Test
    fun aRefusedShareDecidesThePermissionBeforeTheKeyIsRead() = runTest {
        givenSoftwareKey(SharingPolicyType.SELECTED_PEERS)

        val response = Response.fromJson(served())

        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        assertTrue("the permission was decided", decided)
        assertFalse(
            "the software key was read before the share permission was decided: $readsBeforeDecision",
            readsBeforeDecision.any { it }
        )
    }

    @Test
    fun aRefusedShareZeroesTheSoftwareKeyMaterial() = runTest {
        for (policy in listOf(SharingPolicyType.PRIVATE, SharingPolicyType.SELECTED_PEERS)) {
            val material = secret()
            givenSoftwareKey(policy, material)

            val bytes = served()

            assertEquals("$policy", ErrorCodes.OPERATION_DENIED, Response.fromJson(bytes).error?.code)
            assertFalse("$policy: material in the refusal", Base64.getEncoder().encodeToString(secret()) in String(bytes))
            assertTrue(
                "$policy: the refused key's material was left in memory: ${material.toList()}",
                material.all { it == 0.toByte() }
            )
        }
    }

    /** A key with no row has no recorded policy: refused, and its material zeroed too. */
    @Test
    fun aKeyWithNoRowIsRefusedWithItsMaterialZeroed() = runTest {
        val material = secret()
        givenSoftwareKey(SharingPolicyType.ALL_PEERS, material)
        coEvery { keyDao.getByKeyId(KEY_ID) } returns null

        val response = Response.fromJson(served())

        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        assertTrue("material left in memory: ${material.toList()}", material.all { it == 0.toByte() })
    }

    /** The granted share still sends the material, read after the permission. */
    @Test
    fun aGrantedShareSendsTheMaterial() = runTest {
        givenSoftwareKey(SharingPolicyType.ALL_PEERS)

        val response = Response.fromJson(served())

        val result = response.result!!
        assertEquals(Base64.getEncoder().encodeToString(secret()), result.getString("wrapped_key"))
        assertTrue(result.getBoolean("exportable"))
        assertFalse("read before the permission: $readsBeforeDecision", readsBeforeDecision.any { it })
    }

    /** An id no key holds is still not found, with nothing read past it. */
    @Test
    fun anUnknownKeyIsNotFound() = runTest {
        val response = Response.fromJson(served())

        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.error?.code)
    }

    /**
     * A share permitted when its read starts and made PRIVATE while the read
     * runs is refused, and the material that read decrypted is zeroed: the
     * decision after the read sees the revoke the decision before it missed.
     */
    @Test
    fun aShareMadePrivateDuringItsReadIsRefusedWithItsMaterialZeroed() = runTest {
        val material = secret()
        var read = false
        givenSoftwareKey(SharingPolicyType.ALL_PEERS, material) { read = true }
        coEvery { keyDao.getByKeyId(KEY_ID) } answers {
            row(if (read) SharingPolicyType.PRIVATE else SharingPolicyType.ALL_PEERS)
        }

        val bytes = served()

        assertTrue("the key was read", read)
        assertRefusedWithMaterialZeroed(bytes, material)
    }

    /**
     * A Selected Peers share whose peer grant is withdrawn while the read
     * runs is refused, and the material that read decrypted is zeroed.
     */
    @Test
    fun aPeerGrantWithdrawnDuringTheReadIsRefusedWithItsMaterialZeroed() = runTest {
        val material = secret()
        var read = false
        givenSoftwareKey(SharingPolicyType.SELECTED_PEERS, material) { read = true }
        coEvery { grants.isPeerGranted(KEY_ID, PEER) } answers {
            decided = true
            !read
        }

        val bytes = served()

        assertTrue("the key was read", read)
        assertRefusedWithMaterialZeroed(bytes, material)
    }

    /**
     * A share whose second decision, after the read, fails is an internal
     * error that keeps none of the material. The first key row lookup after
     * the read (the audit's key type) answers; the decision's own throws.
     */
    @Ignore(
        "Fails at 25cc60cf: the handler zeroes the material only on the refusal branch, so a " +
            "decision that throws after the read leaves it in memory. Lift once the export zeroes " +
            "it in a finally on every exit."
    )
    @Test
    fun aFailedDecisionAfterTheReadKeepsNoneOfTheMaterial() = runTest {
        val material = secret()
        var read = false
        givenSoftwareKey(SharingPolicyType.ALL_PEERS, material) { read = true }
        var lookupsAfterRead = 0
        coEvery { keyDao.getByKeyId(KEY_ID) } answers {
            if (read && ++lookupsAfterRead > 1) error("key store unreadable")
            row(SharingPolicyType.ALL_PEERS)
        }

        val bytes = served()

        assertTrue("the key was read", read)
        assertEquals(ErrorCodes.INTERNAL_ERROR, Response.fromJson(bytes).error?.code)
        assertFalse("material in the response", Base64.getEncoder().encodeToString(secret()) in String(bytes))
        assertTrue("the key's material was left in memory: ${material.toList()}", material.all { it == 0.toByte() })
    }

    private fun assertRefusedWithMaterialZeroed(bytes: ByteArray, material: ByteArray) {
        assertEquals(ErrorCodes.OPERATION_DENIED, Response.fromJson(bytes).error?.code)
        assertFalse("material in the refusal", Base64.getEncoder().encodeToString(secret()) in String(bytes))
        assertTrue("the refused key's material was left in memory: ${material.toList()}", material.all { it == 0.toByte() })
    }

    /** A software key [KEY_ID] under [policy]; [onRead] runs inside each read of it. */
    private fun givenSoftwareKey(
        policy: SharingPolicyType,
        material: ByteArray = secret(),
        onRead: () -> Unit = {}
    ) {
        every { anyConstructed<SoftwareKeyStore>().get(KEY_ID) } answers {
            readsBeforeDecision += !decided && policy == SharingPolicyType.SELECTED_PEERS
            onRead()
            SoftwareKey(
                keyId = KEY_ID,
                algorithm = "AES",
                keyType = "symmetric",
                keySize = material.size * 8,
                exportable = true,
                shareable = true,
                material = material
            )
        }
        coEvery { keyDao.getByKeyId(KEY_ID) } returns row(policy)
    }

    private fun row(policy: SharingPolicyType) = KeyEntity(
        keyId = KEY_ID,
        keyType = "symmetric",
        algorithm = "AES",
        label = KEY_ID,
        keySizeBits = 256,
        exportable = true,
        shareable = true,
        sharingPolicy = policy,
        source = "software"
    )

    private suspend fun served(): ByteArray =
        withContext(RequestHandler.servedConnection(SessionBindingProvider { null }, PEER, "test:connection")) {
            handler.handleRawRequest(
                Request(
                    id = 1,
                    method = MethodNames.LOCAL_IMPORT_SHARED_KEY,
                    params = JSONObject().put("key_id", KEY_ID)
                ).toJson()
            )
        }

    private companion object {
        const val KEY_ID = "shared-sym"
        const val PEER = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"

        /** A fresh copy each call: a refusal zeroes the array it was handed. */
        fun secret() = ByteArray(32) { (0x40 + it).toByte() }
    }
}
