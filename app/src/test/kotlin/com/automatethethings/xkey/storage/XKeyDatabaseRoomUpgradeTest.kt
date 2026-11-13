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
package com.automatethethings.xkey.storage

import androidx.room.RoomDatabase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What the Room 2.7.0 -> 2.8.5 upgrade must not change for a database
 * already on a device.
 *
 * On open, Room compares the identity hash stored in the device's
 * `room_master_table` with the one compiled into `XKeyDatabase_Impl`, and
 * throws "Room cannot verify the data integrity" when they differ
 * (room-runtime 2.8.5, RoomConnectionManager.kt:287). Since #193 the
 * database is version 13, which adds `key_policies`, and since round 9
 * version 14, which adds `key_deletions`: its identity hash is
 * [V14_IDENTITY_HASH], the hash in the committed `app/schemas/.../14.json`
 * this build exports; if the processor computed another from the same
 * entities (its identityHash inputs: room-compiler vo/Database.kt, Entity,
 * Property, Index, PrimaryKey), a v13 device would fail to open its
 * database. Below v13, the app has no `fallbackToDestructiveMigration*`
 * (XKeyDatabase.buildDatabase), so a device on an older version needs a
 * migration path to 13, or the open throws "A migration from x to 13 was
 * required but not found". Both are checked here against the jars CI builds
 * with, at the current version: v13 (#178) adds the keys table's policy
 * revision, so the compiled hash is now the committed 13.json's, and every
 * stored version from 1 to 12 needs a path to 13. The type converter is covered by [AuditOperationTypeConverterTest];
 * the migrations' SQL is covered on a device by the instrumented
 * `XKeyDatabaseMigrationTest`.
 */
class XKeyDatabaseRoomUpgradeTest {

    /**
     * Turns red if room-compiler 2.8.5 computes a different identity hash or
     * version for `@Database(version = 13)` than the committed 13.json: the generated
     * `createOpenDelegate()` (room-compiler DatabaseWriter.kt:448-470,
     * OpenDelegateWriter.kt:52-58) passes both to the `RoomOpenDelegate`
     * the runtime checks at open. Read by reflection because
     * `createOpenDelegate` is protected and `RoomOpenDelegate` is
     * library-restricted.
     */
    @Test
    fun `generated open delegate carries the identity hash of the committed current schema`() {
        val impl = Class.forName("com.automatethethings.xkey.storage.XKeyDatabase_Impl")
            .getDeclaredConstructor()
            .newInstance()
        val createOpenDelegate = impl.javaClass.getDeclaredMethod("createOpenDelegate")
        createOpenDelegate.isAccessible = true
        val delegate = createOpenDelegate.invoke(impl)

        val delegateType = Class.forName("androidx.room.RoomOpenDelegate")
        assertTrue(delegateType.isInstance(delegate))
        assertEquals(CURRENT_VERSION, delegateType.getMethod("getVersion").invoke(delegate))
        assertEquals(
            "the identity hash current databases hold in room_master_table",
            CURRENT_IDENTITY_HASH,
            delegateType.getMethod("getIdentityHash").invoke(delegate)
        )
    }

    /**
     * Turns red if Room 2.8.5's migration path search
     * (`RoomDatabase.MigrationContainer.findMigrationPath`) no longer finds
     * the app's step-by-step chain from a stored version to 14. With no
     * destructive fallback, a device on that version would then fail to open
     * its database instead of migrating.
     */
    @Test
    fun `every stored version has a migration path to the current one`() {
        val container = RoomDatabase.MigrationContainer()
        container.addMigrations(APP_MIGRATIONS)

        for (start in 1 until CURRENT_VERSION) {
            val path = container.findMigrationPath(start, CURRENT_VERSION)
            assertNotNull("no migration path from v$start to v$CURRENT_VERSION", path)
            assertEquals(
                "path from v$start runs every step in order",
                (start until CURRENT_VERSION).toList(),
                path!!.map { it.startVersion }
            )
            assertEquals(CURRENT_VERSION, path.last().endVersion)
        }
    }

    private companion object {
        /** The version `@Database` declares. */
        const val CURRENT_VERSION = 15

        /**
         * `identityHash` of the committed 15.json (#193: `key_policies` at 14,
         * `key_deletions` at 15, on #178's 13). (12.json, written by Room
         * 2.7.0 in #42, holds 346118e31d0992f85496533bbc1b5d5b, which 2.8.5
         * reproduced for the v12 entities.)
         */
        const val CURRENT_IDENTITY_HASH = "9131d18aa77079c253ca6bd2ee494e1f"

        /** The migrations `XKeyDatabase.buildDatabase` registers, in its order. */
        val APP_MIGRATIONS = listOf(
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
            XKeyDatabase.MIGRATION_12_13,
            XKeyDatabase.MIGRATION_13_14,
            XKeyDatabase.MIGRATION_14_15
        )
    }
}
