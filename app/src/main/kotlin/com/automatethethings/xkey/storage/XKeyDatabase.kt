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

import android.content.Context
import android.util.Log
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.ca.CertificateDao
import com.automatethethings.xkey.ca.CertificateEntity
import com.automatethethings.xkey.storage.dao.ContactDao
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.oath.OathCredentialDao
import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.password.PasswordDao
import com.automatethethings.xkey.password.PasswordEntity
import com.automatethethings.xkey.piv.PivSlotDao
import com.automatethethings.xkey.piv.PivSlotEntity
import com.automatethethings.xkey.storage.entity.ContactEntity
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.KeyPolicyEntity
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import com.automatethethings.xkey.settings.PairedDeviceRepository
import java.util.concurrent.atomic.AtomicReference

/**
 * Room database for storing passkey credential metadata and unified key storage.
 *
 * This database stores metadata about passkey credentials and all key types
 * managed by xKey, while the actual cryptographic keys remain securely
 * stored in Android Keystore. This separation allows for efficient querying
 * and management of credentials and keys without compromising key security.
 *
 * Version history:
 * - v1: Initial schema with `credential_metadata` table for FIDO2 credentials.
 * - v2: Added unified `keys` table for all key types (FIDO2, SSH, TLS, etc.)
 *        with migration of existing credential_metadata rows.
 * - v3: Added `is_system_key` column to `keys` table. Renamed key types to
 *        align with go-xkms: "ssh" -> "signing", "symmetric" -> "secret".
 * - v4: Added per-key sharing policies with `key_sharing_policies` table and
 *        `sharing_policy` column. Migrates legacy `shareable` flag to new policy.
 * - v5: Added `audit_logs` table for comprehensive security event tracking.
 * - v6: Added `certificates` table for X.509 certificate lifecycle management.
 * - v7: Added `contacts` table for recipient public key management.
 * - v8: Added `oath_credentials` table for TOTP/HOTP credential management.
 * - v9: Added `piv_slots` table for PIV smart card key slot management.
 * - v10: Added `passwords` table for the encrypted password manager.
 * - v11: Migrated key source token "keychaind" -> "xkmsd" (go-xkms daemon rename).
 * - v12: Added expires_at, shared and tenant_id columns to passwords table.
 * - v13: Added `key_policies` table: one row per key holding its sharing
 *        policy state, written only by [KeyPolicyStore] (#193).
 *
 * Usage:
 * ```kotlin
 * val database = XKeyDatabase.getInstance(context)
 *
 * // Legacy FIDO2 credential DAO (still used by CredentialProviderService)
 * val credentialDao = database.credentialMetadataDao()
 *
 * // Unified key storage DAO
 * val keyDao = database.keyDao()
 *
 * // Insert a new key
 * keyDao.insert(keyEntity)
 *
 * // Query keys by type
 * val signingKeys = keyDao.getByType("signing")
 * ```
 */
@Database(
    entities = [
        CredentialMetadataEntity::class,
        KeyEntity::class,
        KeySharingPolicy::class,
        AuditLogEntity::class,
        CertificateEntity::class,
        ContactEntity::class,
        OathCredentialEntity::class,
        PivSlotEntity::class,
        PasswordEntity::class,
        KeyPolicyEntity::class
    ],
    version = 13,
    exportSchema = true
)
@TypeConverters(AuditOperationTypeConverter::class)
abstract class XKeyDatabase : RoomDatabase() {

    /**
     * Get the DAO for credential metadata operations.
     *
     * This DAO is retained for backward compatibility with the existing
     * CredentialProviderService implementation.
     */
    abstract fun credentialMetadataDao(): CredentialMetadataDao

    /**
     * Get the DAO for unified key storage operations.
     *
     * This DAO supports all key types: FIDO2, SSH, TLS, signing,
     * encryption, symmetric, and HMAC keys.
     */
    abstract fun keyDao(): KeyDao

    /**
     * Get the DAO for per-key sharing policy operations.
     *
     * This DAO manages fine-grained sharing permissions for keys with
     * specific peer devices. Used when a key's sharingPolicy is set to
     * SELECTED_PEERS.
     */
    abstract fun keySharingPolicyDao(): KeySharingPolicyDao

    /**
     * Get the DAO for a key's policy row and the writes [KeyPolicyStore]
     * composes into its transactions. Use the store, not this DAO.
     */
    abstract fun keyPolicyDao(): KeyPolicyDao

    /**
     * Get the DAO for audit log operations.
     *
     * This DAO provides access to the audit log system for recording and
     * querying security-relevant operations performed by xKey.
     */
    abstract fun auditLogDao(): AuditLogDao

    /**
     * Get the DAO for certificate management operations.
     *
     * This DAO provides access to the certificates table for managing
     * X.509 certificates issued by the local CA.
     */
    abstract fun certificateDao(): CertificateDao

    /**
     * Get the DAO for contact/recipient key management.
     *
     * This DAO provides access to the contacts table for managing
     * recipient public keys used in file encryption and signature verification.
     */
    abstract fun contactDao(): ContactDao

    /**
     * Get the DAO for OATH credential operations.
     *
     * This DAO provides access to the oath_credentials table for managing
     * TOTP/HOTP one-time password credentials.
     */
    abstract fun oathCredentialDao(): OathCredentialDao

    /**
     * Get the DAO for PIV slot operations.
     *
     * This DAO provides access to the piv_slots table for managing
     * NIST SP 800-73 PIV smart card key slots.
     */
    abstract fun pivSlotDao(): PivSlotDao

    /**
     * Get the DAO for password store operations.
     *
     * This DAO provides access to the passwords table for the encrypted
     * password manager.
     */
    abstract fun passwordDao(): PasswordDao

    companion object {
        private const val DATABASE_NAME = "xkey_credentials.db"

        private val instanceRef = AtomicReference<XKeyDatabase?>(null)

        /**
         * Migration from v1 to v2: create unified `keys` table and migrate
         * existing credential_metadata rows into it.
         */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // Create the unified keys table
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `keys` (
                        `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        `key_id` TEXT NOT NULL,
                        `key_type` TEXT NOT NULL,
                        `algorithm` TEXT NOT NULL,
                        `label` TEXT NOT NULL,
                        `public_key_der` BLOB,
                        `public_key_cose` BLOB,
                        `key_size_bits` INTEGER NOT NULL,
                        `strongbox_backed` INTEGER NOT NULL DEFAULT 0,
                        `biometric_required` INTEGER NOT NULL DEFAULT 1,
                        `auth_duration_seconds` INTEGER NOT NULL DEFAULT 5,
                        `exportable` INTEGER NOT NULL DEFAULT 0,
                        `shareable` INTEGER NOT NULL DEFAULT 0,
                        `source` TEXT NOT NULL,
                        `remote_backend` TEXT,
                        `use_count` INTEGER NOT NULL DEFAULT 0,
                        `created_at` INTEGER NOT NULL,
                        `last_used_at` INTEGER NOT NULL DEFAULT 0,
                        `rp_id` TEXT,
                        `rp_name` TEXT,
                        `user_id` TEXT,
                        `user_name` TEXT,
                        `user_display_name` TEXT,
                        `is_discoverable` INTEGER NOT NULL DEFAULT 0,
                        `sign_count` INTEGER NOT NULL DEFAULT 0
                    )
                    """.trimIndent()
                )

                // Create indices on the keys table
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS `index_keys_key_id` ON `keys` (`key_id`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_keys_key_type` ON `keys` (`key_type`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_keys_algorithm` ON `keys` (`algorithm`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_keys_source` ON `keys` (`source`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_keys_rp_id` ON `keys` (`rp_id`)")

                // Migrate existing credential_metadata rows into the keys table
                db.execSQL(
                    """
                    INSERT INTO `keys` (
                        `key_id`, `key_type`, `algorithm`, `label`, `public_key_cose`,
                        `key_size_bits`, `biometric_required`, `source`, `created_at`,
                        `last_used_at`, `rp_id`, `rp_name`, `user_id`, `user_name`,
                        `user_display_name`, `is_discoverable`, `sign_count`
                    )
                    SELECT
                        `credential_id`,
                        'fido2',
                        'ES256',
                        COALESCE(`rp_name`, `rp_id`),
                        `public_key_cose`,
                        256,
                        1,
                        'local',
                        `created_at`,
                        `last_used_at`,
                        `rp_id`,
                        `rp_name`,
                        `user_id`,
                        `user_name`,
                        `user_display_name`,
                        `is_discoverable`,
                        `sign_count`
                    FROM `credential_metadata`
                    """.trimIndent()
                )
            }
        }

        /**
         * Migration from v2 to v3: add is_system_key column and align key types
         * with go-xkms naming conventions.
         *
         * Changes:
         * - Add `is_system_key` column (default 0)
         * - Rename key_type "ssh" -> "signing" (SSH keys are signing keys)
         * - Rename key_type "symmetric" -> "secret" (matches go-xkms Secret type)
         * - Mark framework keys (e.g., _androidx_security_master_k) as system keys
         */
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // Add is_system_key column
                db.execSQL(
                    "ALTER TABLE `keys` ADD COLUMN `is_system_key` INTEGER NOT NULL DEFAULT 0"
                )

                // Rename key types to align with go-xkms
                db.execSQL("UPDATE `keys` SET `key_type` = 'signing' WHERE `key_type` = 'ssh'")
                db.execSQL("UPDATE `keys` SET `key_type` = 'secret' WHERE `key_type` = 'symmetric'")

                // Mark known framework keys as system keys
                db.execSQL(
                    "UPDATE `keys` SET `is_system_key` = 1 WHERE `key_id` LIKE '_androidx_%'"
                )
            }
        }

        /**
         * Migration from v3 to v4: add per-key sharing policies.
         *
         * Changes:
         * - Add `sharing_policy` column to `keys` table (default 'PRIVATE')
         * - Create `key_sharing_policies` table for fine-grained peer access
         * - Migrate legacy `shareable` flag:
         *   - shareable = true -> sharing_policy = 'ALL_PEERS' (backward compatible behavior)
         *   - shareable = false -> sharing_policy = 'PRIVATE'
         */
        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // Add sharing_policy column to keys table
                db.execSQL(
                    "ALTER TABLE `keys` ADD COLUMN `sharing_policy` TEXT NOT NULL DEFAULT 'PRIVATE'"
                )

                // Migrate legacy shareable flag to new sharing policy
                // Keys that were shareable become ALL_PEERS for backward compatibility
                db.execSQL(
                    "UPDATE `keys` SET `sharing_policy` = 'ALL_PEERS' WHERE `shareable` = 1"
                )

                // Create key_sharing_policies table
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `key_sharing_policies` (
                        `key_id` TEXT NOT NULL,
                        `peer_public_key_hex` TEXT NOT NULL,
                        `allowed` INTEGER NOT NULL DEFAULT 1,
                        `created_at` INTEGER NOT NULL,
                        PRIMARY KEY(`key_id`, `peer_public_key_hex`),
                        FOREIGN KEY(`key_id`) REFERENCES `keys`(`key_id`) ON DELETE CASCADE
                    )
                    """.trimIndent()
                )

                // Create indices on key_sharing_policies table
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_key_id` ON `key_sharing_policies` (`key_id`)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_peer_public_key_hex` ON `key_sharing_policies` (`peer_public_key_hex`)"
                )
            }
        }

        /**
         * Migration from v4 to v5: add audit_logs table.
         *
         * Creates the comprehensive audit logging system for tracking
         * security-relevant operations.
         */
        val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // Create audit_logs table
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `audit_logs` (
                        `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        `timestamp` INTEGER NOT NULL,
                        `operation_type` TEXT NOT NULL,
                        `key_id` TEXT,
                        `key_label` TEXT,
                        `key_type` TEXT,
                        `device_id` TEXT,
                        `device_name` TEXT,
                        `success` INTEGER NOT NULL DEFAULT 1,
                        `error_message` TEXT,
                        `details` TEXT,
                        `duration_ms` INTEGER
                    )
                    """.trimIndent()
                )

                // Create indices for efficient querying
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_audit_logs_timestamp` ON `audit_logs` (`timestamp`)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_audit_logs_operation_type` ON `audit_logs` (`operation_type`)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_id` ON `audit_logs` (`key_id`)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_type` ON `audit_logs` (`key_type`)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_audit_logs_device_id` ON `audit_logs` (`device_id`)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_audit_logs_success` ON `audit_logs` (`success`)"
                )
            }
        }

        /**
         * Migration from v5 to v6: add certificates table.
         *
         * Creates the certificates table for X.509 certificate lifecycle
         * management by the local CA.
         */
        val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `certificates` (
                        `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        `serial_number` TEXT NOT NULL,
                        `subject_dn` TEXT NOT NULL,
                        `issuer_dn` TEXT NOT NULL,
                        `not_before` INTEGER NOT NULL,
                        `not_after` INTEGER NOT NULL,
                        `profile` TEXT NOT NULL,
                        `fingerprint` TEXT NOT NULL,
                        `certificate_pem` TEXT NOT NULL,
                        `chain_pem` TEXT,
                        `key_id` TEXT,
                        `device_id` TEXT,
                        `revoked` INTEGER NOT NULL DEFAULT 0,
                        `revoked_at` INTEGER,
                        `revoked_reason` INTEGER,
                        `is_ca` INTEGER NOT NULL DEFAULT 0,
                        `created_at` INTEGER NOT NULL
                    )
                    """.trimIndent()
                )

                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS `index_certificates_serial_number` ON `certificates` (`serial_number`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_certificates_profile` ON `certificates` (`profile`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_certificates_key_id` ON `certificates` (`key_id`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_certificates_revoked` ON `certificates` (`revoked`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_certificates_not_after` ON `certificates` (`not_after`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_certificates_is_ca` ON `certificates` (`is_ca`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_certificates_fingerprint` ON `certificates` (`fingerprint`)")
            }
        }

        /**
         * Migration from v6 to v7: add contacts table.
         *
         * Creates the contacts table for managing recipient public keys
         * used in file encryption and signature verification.
         */
        val MIGRATION_6_7 = object : Migration(6, 7) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `contacts` (
                        `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        `name` TEXT NOT NULL,
                        `public_key_der` BLOB NOT NULL,
                        `public_key_fingerprint` TEXT NOT NULL,
                        `algorithm` TEXT NOT NULL,
                        `imported_at` INTEGER NOT NULL,
                        `source` TEXT NOT NULL,
                        `notes` TEXT
                    )
                    """.trimIndent()
                )

                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS `index_contacts_public_key_fingerprint` ON `contacts` (`public_key_fingerprint`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_contacts_name` ON `contacts` (`name`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_contacts_algorithm` ON `contacts` (`algorithm`)")
            }
        }

        /**
         * Migration from v7 to v8: add oath_credentials table.
         *
         * Creates the oath_credentials table for TOTP/HOTP one-time password
         * credential management.
         */
        val MIGRATION_7_8 = object : Migration(7, 8) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `oath_credentials` (
                        `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        `oath_id` TEXT NOT NULL,
                        `oath_type` TEXT NOT NULL,
                        `algorithm` TEXT NOT NULL,
                        `digits` INTEGER NOT NULL DEFAULT 6,
                        `period_seconds` INTEGER NOT NULL DEFAULT 30,
                        `counter` INTEGER NOT NULL DEFAULT 0,
                        `issuer` TEXT,
                        `account_name` TEXT NOT NULL,
                        `secret_encrypted` BLOB NOT NULL,
                        `source` TEXT NOT NULL DEFAULT 'local',
                        `remote_device_id` TEXT,
                        `created_at` INTEGER NOT NULL,
                        `last_used_at` INTEGER,
                        `use_count` INTEGER NOT NULL DEFAULT 0
                    )
                    """.trimIndent()
                )

                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS `index_oath_credentials_oath_id` ON `oath_credentials` (`oath_id`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_oath_credentials_issuer` ON `oath_credentials` (`issuer`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_oath_credentials_source` ON `oath_credentials` (`source`)")
            }
        }

        /**
         * Migration from v8 to v9: add piv_slots table.
         *
         * Creates the piv_slots table for NIST SP 800-73 PIV smart card
         * key slot management.
         */
        val MIGRATION_8_9 = object : Migration(8, 9) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `piv_slots` (
                        `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        `slot_id` TEXT NOT NULL,
                        `algorithm` TEXT,
                        `public_key_der` BLOB,
                        `certificate_der` BLOB,
                        `has_key` INTEGER NOT NULL DEFAULT 0,
                        `created_at` INTEGER NOT NULL,
                        `last_used_at` INTEGER,
                        `use_count` INTEGER NOT NULL DEFAULT 0
                    )
                    """.trimIndent()
                )

                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS `index_piv_slots_slot_id` ON `piv_slots` (`slot_id`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_piv_slots_has_key` ON `piv_slots` (`has_key`)")
            }
        }

        /**
         * Migration from v9 to v10: add passwords table.
         *
         * Creates the passwords table for the encrypted password manager.
         * Password values are encrypted at rest with the Android Keystore.
         */
        val MIGRATION_9_10 = object : Migration(9, 10) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `passwords` (
                        `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        `password_id` TEXT NOT NULL,
                        `name` TEXT NOT NULL,
                        `title` TEXT,
                        `username` TEXT,
                        `password_encrypted` BLOB NOT NULL,
                        `url` TEXT,
                        `notes` TEXT,
                        `folder_path` TEXT,
                        `source` TEXT NOT NULL DEFAULT 'local',
                        `created_at` INTEGER NOT NULL,
                        `updated_at` INTEGER NOT NULL
                    )
                    """.trimIndent()
                )

                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS `index_passwords_password_id` ON `passwords` (`password_id`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_passwords_name` ON `passwords` (`name`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_passwords_source` ON `passwords` (`source`)")
            }
        }

        /**
         * Migration from v10 to v11: rename the key `source` token "keychaind"
         * to "xkmsd" to match the renamed go-xkms daemon (KeyInfo.source wire
         * conformance).
         */
        val MIGRATION_10_11 = object : Migration(10, 11) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("UPDATE `keys` SET `source` = 'xkmsd' WHERE `source` = 'keychaind'")
            }
        }

        /**
         * Migration from v11 to v12: store a password entry's go-xkms policy
         * fields. `expires_at` is nullable (no expiry); every existing entry is
         * personal (`shared` 0) and belongs to the default tenant (`tenant_id`
         * ''), which is what go-xkms assumes of a request that names none.
         */
        val MIGRATION_11_12 = object : Migration(11, 12) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `passwords` ADD COLUMN `expires_at` TEXT")
                db.execSQL("ALTER TABLE `passwords` ADD COLUMN `shared` INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE `passwords` ADD COLUMN `tenant_id` TEXT NOT NULL DEFAULT ''")
            }
        }

        /**
         * Migration from v12 to v13: every key gets its policy row (#193),
         * bound to its key row and holding its stored policy, and a denial a
         * failed narrowing recorded outside the database is moved into it.
         * [denials] gives those records by key id, each "instance@POLICY"
         * ([PairedDeviceRepository.legacyKeyPolicyDenials]). A record for
         * another key row than the stored one is dropped; a PRIVATE denial
         * also owes the key's grant clear. If the records cannot be read,
         * none is dropped silently: every key is denied to every peer and
         * owes its grant clear until its next policy write, and the records
         * stay where they were. Recorded through the store's choke point,
         * [KeyPolicyStore.owedAtMigration].
         */
        fun migration12To13(denials: () -> Map<String, String>): Migration = object : Migration(12, 13) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `key_policies` (`key_id` TEXT NOT NULL, `key_instance` INTEGER NOT NULL, " +
                        "`sharing_policy` TEXT NOT NULL, `pending_policy` TEXT, `denial` TEXT, `clear_grants` INTEGER NOT NULL, " +
                        "PRIMARY KEY(`key_id`), FOREIGN KEY(`key_instance`) REFERENCES `keys`(`id`) ON UPDATE NO ACTION ON DELETE CASCADE )"
                )
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS `index_key_policies_key_instance` ON `key_policies` (`key_instance`)")
                db.execSQL(
                    "INSERT INTO `key_policies` (`key_id`, `key_instance`, `sharing_policy`, `pending_policy`, `denial`, `clear_grants`) " +
                        "SELECT `key_id`, `id`, `sharing_policy`, NULL, NULL, 0 FROM `keys`"
                )
                KeyPolicyStore.owedAtMigration(db, denials)
            }
        }

        /** [migration12To13] with no recorded denials. */
        val MIGRATION_12_13: Migration = migration12To13 { emptyMap() }

        /**
         * Get the singleton database instance.
         *
         * Uses double-checked locking with AtomicReference for thread-safe
         * lazy initialization without explicit synchronization.
         *
         * @param context Application context.
         * @return The database instance.
         */
        fun getInstance(context: Context): XKeyDatabase {
            return instanceRef.get() ?: synchronized(this) {
                instanceRef.get() ?: buildDatabase(context).also {
                    instanceRef.set(it)
                }
            }
        }

        /**
         * Build the database instance.
         */
        private fun buildDatabase(context: Context): XKeyDatabase {
            // The 12 -> 13 migration moves the key policy denials recorded in
            // the paired-device store; they are dropped there only once the
            // migration has committed (onOpen runs after it).
            val pairedDevices = lazy { PairedDeviceRepository(context.applicationContext) }
            val moved = AtomicReference<Collection<String>>(emptyList())
            return Room.databaseBuilder(
                context.applicationContext,
                XKeyDatabase::class.java,
                DATABASE_NAME
            )
                .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7, MIGRATION_7_8, MIGRATION_8_9, MIGRATION_9_10, MIGRATION_10_11, MIGRATION_11_12)
                .addMigrations(
                    migration12To13 {
                        pairedDevices.value.legacyKeyPolicyDenials().also { moved.set(it.keys) }
                    }
                )
                .addCallback(object : Callback() {
                    override fun onOpen(db: SupportSQLiteDatabase) {
                        val keyIds = moved.getAndSet(emptyList())
                        if (keyIds.isNotEmpty()) pairedDevices.value.dropLegacyKeyPolicyDenials(keyIds)
                    }
                })
                .build()
        }

        /**
         * Close the database and clear the singleton reference.
         *
         * Should only be called during testing or app shutdown.
         */
        fun closeAndClear() {
            instanceRef.getAndSet(null)?.close()
        }
    }
}

/**
 * Room TypeConverter for [AuditOperationType] enum.
 *
 * Converts between the enum and its string name for database storage.
 */
class AuditOperationTypeConverter {
    /**
     * Nullable on both sides because `AuditLogDao.getFiltered` binds a null
     * operation type to mean "no filter". A non-null parameter here makes
     * Kotlin's null check throw before the query ever runs.
     */
    @androidx.room.TypeConverter
    fun fromAuditOperationType(type: AuditOperationType?): String? = type?.name

    @androidx.room.TypeConverter
    fun toAuditOperationType(name: String?): AuditOperationType? =
        name?.let { AuditOperationType.valueOf(it) }
}
