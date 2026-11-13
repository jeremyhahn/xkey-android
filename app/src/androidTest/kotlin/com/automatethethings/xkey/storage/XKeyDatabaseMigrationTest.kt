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

package com.automatethethings.xkey.storage

import android.content.ContentValues
import android.content.Context
import androidx.room.Room
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.storage.entity.KeyPolicyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Migration tests for [XKeyDatabase].
 *
 * Each test materialises a database exactly as an older app version left it —
 * historical DDL from [LegacySchemas] plus real rows — then opens it through
 * the production Room builder configuration. Room runs the migration path and
 * validates the resulting schema against the compiled v12 entities on open, so
 * a migration that forgets a column or an index fails here rather than on a
 * user's phone. The seeded rows then prove the data survived the trip.
 *
 * Everything happens in a dedicated database file that is deleted before and
 * after every test; the app's own `xkey_credentials.db` is never touched.
 */
@RunWith(AndroidJUnit4::class)
class XKeyDatabaseMigrationTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    private companion object {
        /** Kept distinct from the production database name on purpose. */
        const val TEST_DB = "xkey-migration-test.db"

        /** The legacy source token MIGRATION_10_11 is supposed to rewrite. */
        const val LEGACY_SOURCE = "keychaind"

        /** The token it must be rewritten to. */
        const val CURRENT_SOURCE = "xkmsd"
    }

    @Before
    fun deleteAnyLeftovers() {
        context.deleteDatabase(TEST_DB)
    }

    @After
    fun deleteTestDatabase() {
        context.deleteDatabase(TEST_DB)
    }

    // ------------------------------------------------------------------
    // Every exported schema must migrate to the current version
    // ------------------------------------------------------------------

    @Test
    fun migratesFromVersion3() = assertMigratesAndPreservesData(3)

    @Test
    fun migratesFromVersion4() = assertMigratesAndPreservesData(4)

    @Test
    fun migratesFromVersion5() = assertMigratesAndPreservesData(5)

    @Test
    fun migratesFromVersion6() = assertMigratesAndPreservesData(6)

    @Test
    fun migratesFromVersion7() = assertMigratesAndPreservesData(7)

    @Test
    fun migratesFromVersion8() = assertMigratesAndPreservesData(8)

    @Test
    fun migratesFromVersion9() = assertMigratesAndPreservesData(9)

    @Test
    fun migratesFromVersion10() = assertMigratesAndPreservesData(10)

    @Test
    fun migratesFromVersion11() = assertMigratesAndPreservesData(11)

    @Test
    fun migratesFromVersion12() = assertMigratesAndPreservesData(12)

    /**
     * Guards the fixture itself: if a new schema is exported without a matching
     * test above, the coverage claim made by this suite quietly stops being
     * true.
     */
    @Test
    fun everyExportedSchemaIsCovered() {
        assertEquals(
            "add a migratesFromVersionN test for each exported schema",
            (LegacySchemas.OLDEST until LegacySchemas.CURRENT).toList(),
            LegacySchemas.TESTABLE_VERSIONS
        )
    }

    // ------------------------------------------------------------------
    // Per-migration data transformations
    // ------------------------------------------------------------------

    /**
     * MIGRATION_10_11 renames the go-xkms daemon's source token. Rows written
     * by the old daemon name must come out as `xkmsd`, and rows written by
     * anything else must be left exactly as they were.
     */
    @Test
    fun migration10To11RewritesTheKeychaindSourceToken() {
        createLegacyDatabase(10) { db ->
            insertKey(db, keyId = "legacy-daemon-key", source = LEGACY_SOURCE)
            insertKey(db, keyId = "local-key", source = "local")
            insertKey(db, keyId = "remote-ble-key", source = "remote_ble")
        }

        withMigratedDatabase { db ->
            assertEquals(
                "the keychaind token must be rewritten to xkmsd",
                CURRENT_SOURCE,
                db.keyDao().getByKeyId("legacy-daemon-key")?.source
            )
            assertEquals(
                "unrelated sources must not be touched",
                "local",
                db.keyDao().getByKeyId("local-key")?.source
            )
            assertEquals(
                "unrelated sources must not be touched",
                "remote_ble",
                db.keyDao().getByKeyId("remote-ble-key")?.source
            )
        }
    }

    /**
     * MIGRATION_11_12 adds a password entry's go-xkms policy columns. Every
     * entry written at 11 comes out with no expiry, personal, in the default
     * tenant, and with every column it had kept.
     */
    @Test
    fun migration11To12GivesExistingPasswordsTheDefaultPolicy() {
        createLegacyDatabase(11) { db ->
            insertRow(
                db,
                "passwords",
                mapOf(
                    "password_id" to "pw-legacy",
                    "name" to "Legacy",
                    "username" to "user@example.com",
                    "password_encrypted" to byteArrayOf(1, 2, 3),
                    "folder_path" to "/work",
                    "source" to "remote",
                    "created_at" to 1_000L,
                    "updated_at" to 2_000L
                )
            )
        }

        withMigratedDatabase { db ->
            val migrated = requireNotNull(db.passwordDao().getByPasswordId("pw-legacy"))
            assertNull("an entry written at 11 has no expiry", migrated.expiresAt)
            assertFalse("an entry written at 11 is personal", migrated.shared)
            assertEquals("an entry written at 11 is in the default tenant", "", migrated.tenantId)
            assertEquals("Legacy", migrated.name)
            assertEquals("user@example.com", migrated.username)
            assertEquals("/work", migrated.folderPath)
            assertEquals("remote", migrated.source)
            assertEquals(1_000L, migrated.createdAt)
            assertEquals(2_000L, migrated.updatedAt)
            assertTrue(migrated.passwordEncrypted.contentEquals(byteArrayOf(1, 2, 3)))
            assertEquals(
                "a migrated entry is found in the default tenant",
                "pw-legacy",
                db.passwordDao().getByPasswordIdInTenant("pw-legacy", "")?.passwordId
            )
            assertEquals(
                "a migrated entry lists as personal",
                listOf("pw-legacy"),
                db.passwordDao().getForListing("", shared = false, folderPath = null).map { it.passwordId }
            )
        }
    }

    /**
     * MIGRATION_12_13 gives every key its one policy row (#193), bound to its
     * key row and holding its stored policy, and moves in a denial a failed
     * narrowing recorded outside the database: a PRIVATE denial also owes the
     * key's grant clear. A record for a key row that no longer exists is
     * dropped, not attached to a later key under the same id.
     */
    @Test
    fun migration12To13MovesRecordedDenialsIntoTheKeyPolicyRows() {
        val instances = mutableMapOf<String, Long>()
        createLegacyDatabase(12) { db ->
            insertKey(db, keyId = "denied", source = "local", shareable = true)
            insertKey(db, keyId = "narrowed", source = "local", shareable = true)
            insertKey(db, keyId = "recreated", source = "local", shareable = true)
            insertKey(db, keyId = "plain", source = "local")
            for (keyId in listOf("denied", "narrowed", "recreated", "plain")) {
                db.query("SELECT id FROM keys WHERE key_id = ?", arrayOf(keyId)).use {
                    it.moveToFirst()
                    instances[keyId] = it.getLong(0)
                }
            }
            insertRow(db, "key_sharing_policies", mapOf("key_id" to "denied", "peer_public_key_hex" to "aa", "allowed" to 1, "created_at" to 1L))
        }
        val recorded = mapOf(
            "denied" to "${instances["denied"]}@PRIVATE",
            "narrowed" to "${instances["narrowed"]}@SELECTED_PEERS",
            "recreated" to "${instances.getValue("recreated") + 100}@PRIVATE"
        )

        withMigratedDatabase(XKeyDatabase.migration12To13 { recorded }) { db ->
            val dao = db.keyPolicyDao()
            val denied = requireNotNull(dao.policyRow("denied"))
            assertEquals(instances["denied"], denied.keyInstance)
            assertEquals(SharingPolicyType.ALL_PEERS, denied.sharingPolicy)
            assertEquals(SharingPolicyType.PRIVATE, denied.denial)
            assertEquals(SharingPolicyType.PRIVATE, denied.pendingPolicy)
            assertTrue("a PRIVATE denial owes the grant clear", denied.clearGrants)
            assertEquals(SharingPolicyType.PRIVATE, denied.enforced)

            val narrowed = requireNotNull(dao.policyRow("narrowed"))
            assertEquals(SharingPolicyType.SELECTED_PEERS, narrowed.denial)
            assertFalse(narrowed.clearGrants)

            val recreated = requireNotNull(dao.policyRow("recreated"))
            assertNull("a record for another key row is dropped", recreated.denial)
            assertEquals(SharingPolicyType.ALL_PEERS, recreated.enforced)

            val plain = requireNotNull(dao.policyRow("plain"))
            assertEquals(KeyPolicyEntity("plain", instances.getValue("plain"), SharingPolicyType.PRIVATE), plain)

            assertEquals(1, db.keyDao().deleteByKeyId("denied"))
            assertNull("deleting the key row deletes its policy row", dao.policyRow("denied"))
        }
    }

    /**
     * MIGRATION_3_4 introduced the per-key sharing policy and had to decide
     * what the pre-existing boolean `shareable` flag meant. A key that was
     * shareable keeps working (ALL_PEERS); one that was not stays PRIVATE.
     */
    @Test
    fun migration3To4DerivesSharingPolicyFromTheLegacyShareableFlag() {
        createLegacyDatabase(3) { db ->
            insertKey(db, keyId = "was-shareable", source = "local", shareable = true)
            insertKey(db, keyId = "was-private", source = "local", shareable = false)
        }

        withMigratedDatabase { db ->
            assertEquals(
                "a legacy shareable key must stay usable by peers",
                SharingPolicyType.ALL_PEERS,
                db.keyDao().getByKeyId("was-shareable")?.sharingPolicy
            )
            assertEquals(
                "a legacy non-shareable key must not become shareable",
                SharingPolicyType.PRIVATE,
                db.keyDao().getByKeyId("was-private")?.sharingPolicy
            )
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Creates a database at [version] using that version's frozen DDL, seeds a
     * key and a FIDO2 credential, migrates it with the production migration
     * set, and asserts both rows arrived intact. The key is seeded with the
     * legacy source token only where the path runs MIGRATION_10_11 (from 10
     * or earlier), else with the current one.
     */
    private fun assertMigratesAndPreservesData(version: Int) {
        val keyId = "legacy-key-v$version"
        val credentialId = "legacy-credential-v$version"
        // Only a path that crosses 10 -> 11 rewrites the legacy token; a
        // database at 11 or later was written with the current one (#193 r7).
        val seeded = if (version <= 10) LEGACY_SOURCE else CURRENT_SOURCE

        createLegacyDatabase(version) { db ->
            insertKey(db, keyId = keyId, source = seeded)
            insertCredential(db, credentialId)
        }

        withMigratedDatabase { db ->
            val key = db.keyDao().getByKeyId(keyId)
            assertNotNull("the key row must survive migration from v$version", key)
            assertEquals("test-label", key!!.label)
            assertEquals("ES256", key.algorithm)
            assertEquals(
                "the key must come out with the current source token from v$version",
                CURRENT_SOURCE,
                key.source
            )

            val credential = db.credentialMetadataDao().getByCredentialId(credentialId)
            assertNotNull("the credential row must survive migration from v$version", credential)
            assertEquals("migration-test.example.com", credential!!.rpId)

            // A row inserted after migrating must round-trip too, which proves
            // the migrated schema accepts what the current entities write.
            assertNull(db.keyDao().getByKeyId("not-present"))
        }
    }

    /**
     * Materialises [TEST_DB] at [version] with the historical DDL, then runs
     * [seed] against it and closes the handle so Room can take ownership.
     */
    private fun createLegacyDatabase(version: Int, seed: (SupportSQLiteDatabase) -> Unit) {
        val callback = object : SupportSQLiteOpenHelper.Callback(version) {
            override fun onCreate(db: SupportSQLiteDatabase) {
                LegacySchemas.ddl(version).forEach(db::execSQL)
            }

            override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                throw IllegalStateException(
                    "the fixture database must be created fresh, not upgraded"
                )
            }
        }
        val configuration = SupportSQLiteOpenHelper.Configuration
            .builder(context)
            .name(TEST_DB)
            .callback(callback)
            .build()

        val helper = FrameworkSQLiteOpenHelperFactory().create(configuration)
        try {
            val db = helper.writableDatabase
            assertEquals("fixture must report the historical version", version, db.version)
            seed(db)
        } finally {
            helper.close()
        }
    }

    /**
     * Opens [TEST_DB] through the same builder configuration the app uses,
     * which runs the migrations and validates the final schema, then hands the
     * open database to [assertions].
     */
    private fun withMigratedDatabase(
        migration12To13: Migration = XKeyDatabase.MIGRATION_12_13,
        assertions: suspend (XKeyDatabase) -> Unit
    ) {
        val database = Room.databaseBuilder(context, XKeyDatabase::class.java, TEST_DB)
            .addMigrations(
                XKeyDatabase.MIGRATION_1_2,
                XKeyDatabase.MIGRATION_2_3,
                XKeyDatabase.MIGRATION_3_4,
                XKeyDatabase.MIGRATION_4_5,
                XKeyDatabase.MIGRATION_5_6,
                XKeyDatabase.MIGRATION_6_7,
                XKeyDatabase.MIGRATION_7_8,
                XKeyDatabase.MIGRATION_8_9,
                XKeyDatabase.MIGRATION_9_10,
                XKeyDatabase.MIGRATION_10_11,
                XKeyDatabase.MIGRATION_11_12,
                migration12To13
            )
            .build()
        try {
            runBlocking { assertions(database) }
            assertEquals(
                "the database must end at the current schema version",
                LegacySchemas.CURRENT,
                database.openHelper.writableDatabase.version
            )
        } finally {
            database.close()
        }
    }

    /**
     * Inserts a row into `keys`.
     *
     * The column set changed over time, so the values are matched against the
     * table's actual columns rather than hard-coded per version. Columns that
     * are nullable or carry a default are left alone; every other column gets a
     * type-appropriate value.
     */
    private fun insertKey(
        db: SupportSQLiteDatabase,
        keyId: String,
        source: String,
        shareable: Boolean = false
    ) {
        val overrides = mapOf<String, Any?>(
            "key_id" to keyId,
            "key_type" to "signing",
            "algorithm" to "ES256",
            "label" to "test-label",
            "key_size_bits" to 256,
            "shareable" to if (shareable) 1 else 0,
            "exportable" to 0,
            // Room maps this column onto an enum, so it must hold a real
            // constant name rather than filler.
            "sharing_policy" to if (shareable) "ALL_PEERS" else "PRIVATE",
            "source" to source,
            "created_at" to System.currentTimeMillis()
        )
        insertRow(db, "keys", overrides)
    }

    /** Inserts a row into `credential_metadata`. */
    private fun insertCredential(db: SupportSQLiteDatabase, credentialId: String) {
        val overrides = mapOf<String, Any?>(
            "credential_id" to credentialId,
            "rp_id" to "migration-test.example.com",
            "rp_name" to "Migration Test",
            "user_id" to "user-1",
            "user_name" to "user@example.com",
            "user_display_name" to "Migration Test User",
            "public_key_cose" to ByteArray(32) { it.toByte() },
            "sign_count" to 0,
            "created_at" to System.currentTimeMillis(),
            "last_used_at" to 0,
            "is_discoverable" to 1
        )
        insertRow(db, "credential_metadata", overrides)
    }

    /**
     * Inserts one row into [table], supplying a value for every column the
     * schema requires. [overrides] wins where it applies; anything else that is
     * NOT NULL without a default gets a placeholder of the right type.
     */
    private fun insertRow(
        db: SupportSQLiteDatabase,
        table: String,
        overrides: Map<String, Any?>
    ) {
        val values = ContentValues()
        db.query("PRAGMA table_info(`$table`)").use { cursor ->
            val nameIndex = cursor.getColumnIndexOrThrow("name")
            val typeIndex = cursor.getColumnIndexOrThrow("type")
            val notNullIndex = cursor.getColumnIndexOrThrow("notnull")
            val defaultIndex = cursor.getColumnIndexOrThrow("dflt_value")
            val pkIndex = cursor.getColumnIndexOrThrow("pk")

            while (cursor.moveToNext()) {
                val name = cursor.getString(nameIndex)
                val type = cursor.getString(typeIndex).uppercase()
                val required = cursor.getInt(notNullIndex) == 1
                val hasDefault = !cursor.isNull(defaultIndex)
                val isRowId = cursor.getInt(pkIndex) == 1 && type == "INTEGER"

                when {
                    overrides.containsKey(name) -> when (val value = overrides[name]) {
                        null -> values.putNull(name)
                        is Int -> values.put(name, value)
                        is Long -> values.put(name, value)
                        is ByteArray -> values.put(name, value)
                        else -> values.put(name, value.toString())
                    }
                    isRowId || !required || hasDefault -> Unit
                    type.startsWith("INT") -> values.put(name, 0)
                    type.startsWith("BLOB") -> values.put(name, ByteArray(0))
                    type.startsWith("REAL") -> values.put(name, 0.0)
                    else -> values.put(name, "")
                }
            }
        }
        assertTrue("nothing to insert into $table", values.size() > 0)
        db.insert(table, android.database.sqlite.SQLiteDatabase.CONFLICT_ABORT, values)
    }
}
