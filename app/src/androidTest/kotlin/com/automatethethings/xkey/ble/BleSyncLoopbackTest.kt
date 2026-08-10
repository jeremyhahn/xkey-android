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

package com.automatethethings.xkey.ble

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.truststore.TrustStoreRepository
import com.automatethethings.xkey.ui.TestCertificates
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Sync-family tests over the BLE loopback.
 *
 * `local.syncTrustStore` / `syncOATH` / `syncPasswords` / `syncStatus` are what
 * `xkey device sync` drives from the desktop, and over BLE they had no coverage
 * at all. Each test seeds only its own rows, asserts on those rows rather than
 * on store totals, and removes them in [tearDown] — other suites assert on
 * empty stores and leaked sync rows have broken them before.
 */
@RunWith(AndroidJUnit4::class)
class BleSyncLoopbackTest {

    private lateinit var context: Context
    private lateinit var pairedDeviceRepository: PairedDeviceRepository
    private lateinit var trustStore: TrustStoreRepository
    private lateinit var harness: BleLoopbackHarness

    /** Everything this suite persists, torn down in [tearDown]. */
    private val pairedKeys = mutableListOf<String>()
    private val passwordIds = mutableListOf<String>()
    private val oathAccountNames = mutableListOf<String>()
    private val certFingerprints = mutableListOf<String>()
    private val keystoreAliases = mutableListOf<String>()

    /** Unique per-run suffix so repeated runs never collide. */
    private val runId = System.nanoTime().toString(36)

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        pairedDeviceRepository = PairedDeviceRepository(context)
        trustStore = TrustStoreRepository(context)
        harness = pairedHarness()
    }

    @After
    fun tearDown(): Unit = runBlocking {
        if (::harness.isInitialized) harness.close()
        pairedKeys.forEach { pairedDeviceRepository.removeDevice(it) }

        val db = XKeyDatabase.getInstance(context)
        val passwordDao = db.passwordDao()
        passwordIds.forEach { passwordDao.deleteByPasswordId(it) }

        // OATH rows are keyed by a generated id, so clean up by account name —
        // and by every row that matches, because an import creates a new row.
        val oathDao = db.oathCredentialDao()
        oathDao.getAll()
            .filter { oathAccountNames.contains(it.accountName) }
            .forEach { oathDao.deleteByOathId(it.oathId) }

        certFingerprints.forEach { trustStore.deleteCertificate(it) }
        keystoreAliases.forEach { TestCertificates.deleteAlias(it) }
    }

    // -----------------------------------------------------------------
    // Status
    // -----------------------------------------------------------------

    /** `syncStatus` is what the desktop polls to decide whether to sync at all. */
    @Test
    fun syncStatusReportsDeviceIdAndPerStoreChecksums(): Unit = runBlocking {
        val status = harness.call("local.syncStatus")

        assertTrue("a device id is required for sync attribution", status.getString("device_id").isNotEmpty())
        assertTrue("last_sync must always be present", status.has("last_sync"))

        val checksums = status.getJSONObject("store_checksums")
        assertTrue("oath checksum missing", checksums.getString("oath").isNotEmpty())
        assertTrue("passwords checksum missing", checksums.getString("passwords").isNotEmpty())
        assertTrue("trust_store checksum missing", checksums.getString("trust_store").isNotEmpty())
    }

    /** A password added over the wire must change the password checksum. */
    @Test
    fun syncStatusChecksumTracksTheStoreContents(): Unit = runBlocking {
        val before = harness.call("local.syncStatus")
            .getJSONObject("store_checksums").getString("passwords")

        pushPassword(passwordId("checksum"), "checksum-probe")

        val after = harness.call("local.syncStatus")
            .getJSONObject("store_checksums").getString("passwords")
        assertTrue("the checksum must move when the store changes", before != after)
    }

    // -----------------------------------------------------------------
    // Passwords
    // -----------------------------------------------------------------

    /**
     * The desktop pushes its entries and gets the phone's back in the same
     * round trip; a second push of the same id updates instead of duplicating.
     */
    @Test
    fun syncPasswordsAddsThenUpdatesAndReturnsTheRemoteEntry(): Unit = runBlocking {
        val id = passwordId("pw")

        val added = pushPassword(id, "first-secret")
        assertEquals(1, added.getInt("added"))
        assertEquals(0, added.getInt("updated"))
        assertEquals(0, added.getInt("skipped"))

        val mine = findById(added.getJSONArray("remote"), id)
        assertNotNull("the phone must return the entry it just merged", mine)
        assertEquals("first-secret", mine!!.getString("password"))
        assertEquals("sync-user@example.com", mine.getString("username"))
        assertTrue("entries must carry an updated_at for conflict resolution", mine.getString("updated_at").isNotEmpty())

        val updated = pushPassword(id, "second-secret")
        assertEquals(0, updated.getInt("added"))
        assertEquals(1, updated.getInt("updated"))
        assertEquals(
            "re-syncing must not duplicate the entry",
            "second-secret",
            findById(updated.getJSONArray("remote"), id)!!.getString("password")
        )
    }

    /** Entries the contract cannot key or store are counted as skipped, not merged. */
    @Test
    fun syncPasswordsSkipsUnusableEntries(): Unit = runBlocking {
        val result = harness.call(
            "local.syncPasswords",
            JSONObject().put(
                "passwords",
                JSONArray()
                    .put(JSONObject().put("id", "").put("password", "no-id"))
                    .put(JSONObject().put("id", passwordId("no-password")))
            )
        )

        assertEquals(0, result.getInt("added"))
        assertEquals(0, result.getInt("updated"))
        assertEquals(2, result.getInt("skipped"))
        assertNull(
            "a skipped entry must not reach the store",
            findById(result.getJSONArray("remote"), passwordId("no-password"))
        )
    }

    /** An empty push is a pull: the phone still returns its own entries. */
    @Test
    fun emptySyncStillReturnsThePhonesEntries(): Unit = runBlocking {
        val id = passwordId("pull")
        pushPassword(id, "pull-secret")

        val pulled = harness.call(
            "local.syncPasswords",
            JSONObject().put("passwords", JSONArray())
        )
        assertEquals(0, pulled.getInt("added"))
        assertNotNull(
            "an empty push must still return the phone's store",
            findById(pulled.getJSONArray("remote"), id)
        )
    }

    // -----------------------------------------------------------------
    // OATH
    // -----------------------------------------------------------------

    /**
     * OATH secrets replicate in Base32 over the Noise channel, so the phone must
     * return the credential with a usable secret rather than a redacted one.
     */
    @Test
    fun syncOathMergesCredentialAndReturnsItWithItsSecret(): Unit = runBlocking {
        val accountName = "ble-sync-$runId@example.com"
        oathAccountNames += accountName

        val result = harness.call(
            "local.syncOATH",
            JSONObject().put(
                "credentials",
                JSONArray().put(
                    JSONObject()
                        .put("id", "ble-oath-$runId")
                        .put("name", "ble-oath-$runId")
                        .put("issuer", "BleSyncTest")
                        .put("account_name", accountName)
                        .put("secret", OATH_SECRET)
                        .put("type", "totp")
                        .put("algorithm", "SHA1")
                        .put("digits", 6)
                        .put("period", 30)
                )
            )
        )

        assertEquals(1, result.getInt("added"))
        assertEquals(0, result.getInt("skipped"))

        val remote = result.getJSONArray("remote")
        val mine = (0 until remote.length())
            .map { remote.getJSONObject(it) }
            .firstOrNull { it.optString("account_name") == accountName }
        assertNotNull("the merged credential must come back in the remote list", mine)
        assertEquals(OATH_SECRET, mine!!.getString("secret"))
        assertEquals("BleSyncTest", mine.getString("issuer"))
        assertEquals("totp", mine.getString("type"))
        assertEquals(6, mine.getInt("digits"))
        assertEquals(30, mine.getInt("period"))
    }

    /** Credentials missing the fields the contract requires are skipped. */
    @Test
    fun syncOathSkipsIncompleteCredentials(): Unit = runBlocking {
        val result = harness.call(
            "local.syncOATH",
            JSONObject().put(
                "credentials",
                JSONArray()
                    .put(JSONObject().put("id", "no-secret-$runId").put("account_name", "a@b.c"))
                    .put(JSONObject().put("id", "no-account-$runId").put("secret", OATH_SECRET))
                    .put(JSONObject().put("secret", OATH_SECRET).put("account_name", "a@b.c"))
            )
        )

        assertEquals(0, result.getInt("added"))
        assertEquals(0, result.getInt("updated"))
        assertEquals(3, result.getInt("skipped"))
    }

    // -----------------------------------------------------------------
    // Trust store
    // -----------------------------------------------------------------

    /**
     * A certificate the phone already holds must be skipped by fingerprint and
     * still be handed back so the desktop can merge it.
     */
    @Test
    fun syncTrustStoreSkipsKnownCertificatesAndReturnsThem(): Unit = runBlocking {
        val alias = "ble-sync-ca-$runId"
        keystoreAliases += alias
        val certificate = TestCertificates.selfSigned(alias, "BLE Sync Test CA $runId")
        val fingerprint = trustStore.importInternalCACertificate(certificate, "BLE Sync Test")
        certFingerprints += fingerprint

        val result = harness.call(
            "local.syncTrustStore",
            JSONObject().put(
                "certificates",
                JSONArray().put(
                    JSONObject()
                        .put("pem", TestCertificates.toPem(certificate))
                        .put("fingerprint", fingerprint)
                        .put("source", "desktop")
                )
            )
        )

        assertEquals("a certificate already held must not be re-imported", 0, result.getInt("added"))
        assertEquals(1, result.getInt("skipped"))

        val remote = result.getJSONArray("remote")
        val mine = (0 until remote.length())
            .map { remote.getJSONObject(it) }
            .firstOrNull { it.optString("fingerprint") == fingerprint }
        assertNotNull("the phone must return its own trust store", mine)
        assertTrue(mine!!.getString("pem").startsWith("-----BEGIN CERTIFICATE-----"))
        assertTrue("each entry must carry its source", mine.getString("source").isNotEmpty())
    }

    /** A certificate that cannot be decoded is skipped rather than aborting the sync. */
    @Test
    fun syncTrustStoreSkipsUndecodableCertificates(): Unit = runBlocking {
        val result = harness.call(
            "local.syncTrustStore",
            JSONObject().put(
                "certificates",
                JSONArray().put(
                    JSONObject()
                        .put("pem", "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----")
                        .put("fingerprint", "ff".repeat(32))
                )
            )
        )

        assertEquals(0, result.getInt("added"))
        assertEquals(1, result.getInt("skipped"))
    }

    // -----------------------------------------------------------------
    // Transport interaction
    // -----------------------------------------------------------------

    /**
     * Sync payloads are the largest messages the transport carries, so they are
     * the ones that actually exercise fragmentation. This runs a full sync at a
     * 20-byte payload budget, forcing hundreds of fragments in both directions.
     */
    @Test
    fun syncSurvivesHeavyFragmentation(): Unit = runBlocking {
        val small = pairedHarness(fragmentPayloadSize = 20)
        try {
            val id = passwordId("fragmented")
            passwordIds += id
            val notes = "n".repeat(2048)

            val result = small.call(
                "local.syncPasswords",
                JSONObject().put(
                    "passwords",
                    JSONArray().put(
                        JSONObject()
                            .put("id", id)
                            .put("name", "Fragmented Entry")
                            .put("password", "fragmented-secret")
                            .put("notes", notes)
                            .put("updated_at", "2026-01-01T00:00:00Z")
                    )
                )
            )

            assertEquals(1, result.getInt("added"))
            val mine = findById(result.getJSONArray("remote"), id)
            assertNotNull("the entry must survive the round trip", mine)
            assertEquals(notes, mine!!.getString("notes"))
        } finally {
            small.close()
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** Builds a harness that has completed the handshake and been approved. */
    private fun pairedHarness(
        fragmentPayloadSize: Int = Fragmenter.DEFAULT_PAYLOAD_SIZE
    ): BleLoopbackHarness {
        val created = BleLoopbackHarness(
            context = context,
            pairedDeviceRepository = pairedDeviceRepository,
            pairingCallback = object : PairingConfirmationCallback {
                override suspend fun onPairingConfirmationRequired(
                    deviceName: String,
                    publicKeyFingerprint: String
                ): Boolean = true
            },
            fragmentPayloadSize = fragmentPayloadSize
        )
        runBlocking {
            created.connect()
            // Track the key before pairing so a failure mid-way still cleans up.
            pairedKeys += created.publicKeyHex
            assertTrue(created.confirmPairing("BleSyncLoopbackTest").optBoolean("confirmed"))
        }
        return created
    }

    private fun passwordId(suffix: String) = "ble-sync-$suffix-$runId"

    private suspend fun pushPassword(id: String, password: String): JSONObject {
        if (!passwordIds.contains(id)) passwordIds += id
        return harness.call(
            "local.syncPasswords",
            JSONObject().put(
                "passwords",
                JSONArray().put(
                    JSONObject()
                        .put("id", id)
                        .put("name", "BLE Sync $id")
                        .put("username", "sync-user@example.com")
                        .put("password", password)
                        .put("updated_at", "2026-01-01T00:00:00Z")
                )
            )
        )
    }

    private fun findById(array: JSONArray, id: String): JSONObject? =
        (0 until array.length())
            .map { array.getJSONObject(it) }
            .firstOrNull { it.optString("id") == id }

    private companion object {
        /** A valid Base32 TOTP secret. */
        const val OATH_SECRET = "JBSWY3DPEHPK3PXP"
    }
}
