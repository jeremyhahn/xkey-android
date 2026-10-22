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

/**
 * Frozen DDL for every historical [XKeyDatabase] schema, transcribed verbatim
 * from the exported schema JSONs in `app/schemas`.
 *
 * Room's own `MigrationTestHelper` reads those JSONs from the androidTest
 * assets, which requires both the `androidx.room:room-testing` dependency and
 * an `androidTest.assets.srcDirs += schemas` entry in the build script. Neither
 * is configured for this module, so this object carries the same information in
 * source form: creating a database from [ddl] reproduces exactly the on-disk
 * shape a user of that app version would have, including the
 * `room_master_table` identity hash Room checks when it opens the file.
 *
 * Only versions 3..11 are present because only those schema JSONs were ever
 * exported; schemas 1 and 2 predate `exportSchema`, so migrations 1->2 and 2->3
 * cannot be reproduced faithfully and are not covered.
 */
object LegacySchemas {

    /** The oldest schema version with an exported JSON, hence testable. */
    const val OLDEST = 3

    /** The schema version the app currently ships. */
    const val CURRENT = 12

    /** Every version that can serve as a migration starting point. */
    val TESTABLE_VERSIONS: List<Int> get() = SCHEMAS.keys.sorted()

    /**
     * DDL for [version]: table and index creation, then Room's
     * `room_master_table` seeded with that version's identity hash.
     */
    fun ddl(version: Int): List<String> = requireNotNull(SCHEMAS[version]) {
        "no exported schema for version $version"
    }

    private val SCHEMAS: Map<Int, List<String>> = mapOf(
        3 to listOf(
            "CREATE TABLE IF NOT EXISTS `credential_metadata` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `credential_id` TEXT NOT NULL, `rp_id` TEXT NOT NULL, `rp_name` TEXT NOT NULL, `user_id` TEXT NOT NULL, `user_name` TEXT NOT NULL, `user_display_name` TEXT NOT NULL, `public_key_cose` BLOB NOT NULL, `sign_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `is_discoverable` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_credential_metadata_credential_id` ON `credential_metadata` (`credential_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_rp_id` ON `credential_metadata` (`rp_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_user_id_rp_id` ON `credential_metadata` (`user_id`, `rp_id`)",
            "CREATE TABLE IF NOT EXISTS `keys` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `key_id` TEXT NOT NULL, `key_type` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `label` TEXT NOT NULL, `public_key_der` BLOB, `public_key_cose` BLOB, `key_size_bits` INTEGER NOT NULL, `strongbox_backed` INTEGER NOT NULL, `biometric_required` INTEGER NOT NULL, `auth_duration_seconds` INTEGER NOT NULL, `exportable` INTEGER NOT NULL, `shareable` INTEGER NOT NULL, `source` TEXT NOT NULL, `remote_backend` TEXT, `use_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `rp_id` TEXT, `rp_name` TEXT, `user_id` TEXT, `user_name` TEXT, `user_display_name` TEXT, `is_discoverable` INTEGER NOT NULL, `sign_count` INTEGER NOT NULL, `is_system_key` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_keys_key_id` ON `keys` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_key_type` ON `keys` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_algorithm` ON `keys` (`algorithm`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_source` ON `keys` (`source`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_rp_id` ON `keys` (`rp_id`)",
            "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)",
            "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, 'c4183a69f81acae83121f31692c57cc2')"
        ),
        4 to listOf(
            "CREATE TABLE IF NOT EXISTS `credential_metadata` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `credential_id` TEXT NOT NULL, `rp_id` TEXT NOT NULL, `rp_name` TEXT NOT NULL, `user_id` TEXT NOT NULL, `user_name` TEXT NOT NULL, `user_display_name` TEXT NOT NULL, `public_key_cose` BLOB NOT NULL, `sign_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `is_discoverable` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_credential_metadata_credential_id` ON `credential_metadata` (`credential_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_rp_id` ON `credential_metadata` (`rp_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_user_id_rp_id` ON `credential_metadata` (`user_id`, `rp_id`)",
            "CREATE TABLE IF NOT EXISTS `keys` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `key_id` TEXT NOT NULL, `key_type` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `label` TEXT NOT NULL, `public_key_der` BLOB, `public_key_cose` BLOB, `key_size_bits` INTEGER NOT NULL, `strongbox_backed` INTEGER NOT NULL, `biometric_required` INTEGER NOT NULL, `auth_duration_seconds` INTEGER NOT NULL, `exportable` INTEGER NOT NULL, `shareable` INTEGER NOT NULL, `sharing_policy` TEXT NOT NULL, `source` TEXT NOT NULL, `remote_backend` TEXT, `use_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `rp_id` TEXT, `rp_name` TEXT, `user_id` TEXT, `user_name` TEXT, `user_display_name` TEXT, `is_discoverable` INTEGER NOT NULL, `sign_count` INTEGER NOT NULL, `is_system_key` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_keys_key_id` ON `keys` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_key_type` ON `keys` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_algorithm` ON `keys` (`algorithm`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_source` ON `keys` (`source`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_rp_id` ON `keys` (`rp_id`)",
            "CREATE TABLE IF NOT EXISTS `key_sharing_policies` (`key_id` TEXT NOT NULL, `peer_public_key_hex` TEXT NOT NULL, `allowed` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, PRIMARY KEY(`key_id`, `peer_public_key_hex`), FOREIGN KEY(`key_id`) REFERENCES `keys`(`key_id`) ON UPDATE NO ACTION ON DELETE CASCADE )",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_key_id` ON `key_sharing_policies` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_peer_public_key_hex` ON `key_sharing_policies` (`peer_public_key_hex`)",
            "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)",
            "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, '581779dfe18b8fe84a02fa8ddc6b7cc1')"
        ),
        5 to listOf(
            "CREATE TABLE IF NOT EXISTS `credential_metadata` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `credential_id` TEXT NOT NULL, `rp_id` TEXT NOT NULL, `rp_name` TEXT NOT NULL, `user_id` TEXT NOT NULL, `user_name` TEXT NOT NULL, `user_display_name` TEXT NOT NULL, `public_key_cose` BLOB NOT NULL, `sign_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `is_discoverable` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_credential_metadata_credential_id` ON `credential_metadata` (`credential_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_rp_id` ON `credential_metadata` (`rp_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_user_id_rp_id` ON `credential_metadata` (`user_id`, `rp_id`)",
            "CREATE TABLE IF NOT EXISTS `keys` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `key_id` TEXT NOT NULL, `key_type` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `label` TEXT NOT NULL, `public_key_der` BLOB, `public_key_cose` BLOB, `key_size_bits` INTEGER NOT NULL, `strongbox_backed` INTEGER NOT NULL, `biometric_required` INTEGER NOT NULL, `auth_duration_seconds` INTEGER NOT NULL, `exportable` INTEGER NOT NULL, `shareable` INTEGER NOT NULL, `sharing_policy` TEXT NOT NULL, `source` TEXT NOT NULL, `remote_backend` TEXT, `use_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `rp_id` TEXT, `rp_name` TEXT, `user_id` TEXT, `user_name` TEXT, `user_display_name` TEXT, `is_discoverable` INTEGER NOT NULL, `sign_count` INTEGER NOT NULL, `is_system_key` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_keys_key_id` ON `keys` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_key_type` ON `keys` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_algorithm` ON `keys` (`algorithm`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_source` ON `keys` (`source`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_rp_id` ON `keys` (`rp_id`)",
            "CREATE TABLE IF NOT EXISTS `key_sharing_policies` (`key_id` TEXT NOT NULL, `peer_public_key_hex` TEXT NOT NULL, `allowed` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, PRIMARY KEY(`key_id`, `peer_public_key_hex`), FOREIGN KEY(`key_id`) REFERENCES `keys`(`key_id`) ON UPDATE NO ACTION ON DELETE CASCADE )",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_key_id` ON `key_sharing_policies` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_peer_public_key_hex` ON `key_sharing_policies` (`peer_public_key_hex`)",
            "CREATE TABLE IF NOT EXISTS `audit_logs` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `timestamp` INTEGER NOT NULL, `operation_type` TEXT NOT NULL, `key_id` TEXT, `key_label` TEXT, `key_type` TEXT, `device_id` TEXT, `device_name` TEXT, `success` INTEGER NOT NULL, `error_message` TEXT, `details` TEXT, `duration_ms` INTEGER)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_timestamp` ON `audit_logs` (`timestamp`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_operation_type` ON `audit_logs` (`operation_type`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_id` ON `audit_logs` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_type` ON `audit_logs` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_device_id` ON `audit_logs` (`device_id`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_success` ON `audit_logs` (`success`)",
            "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)",
            "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, '7d4c7a3d6516b5ca838a336459751ec9')"
        ),
        6 to listOf(
            "CREATE TABLE IF NOT EXISTS `credential_metadata` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `credential_id` TEXT NOT NULL, `rp_id` TEXT NOT NULL, `rp_name` TEXT NOT NULL, `user_id` TEXT NOT NULL, `user_name` TEXT NOT NULL, `user_display_name` TEXT NOT NULL, `public_key_cose` BLOB NOT NULL, `sign_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `is_discoverable` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_credential_metadata_credential_id` ON `credential_metadata` (`credential_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_rp_id` ON `credential_metadata` (`rp_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_user_id_rp_id` ON `credential_metadata` (`user_id`, `rp_id`)",
            "CREATE TABLE IF NOT EXISTS `keys` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `key_id` TEXT NOT NULL, `key_type` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `label` TEXT NOT NULL, `public_key_der` BLOB, `public_key_cose` BLOB, `key_size_bits` INTEGER NOT NULL, `strongbox_backed` INTEGER NOT NULL, `biometric_required` INTEGER NOT NULL, `auth_duration_seconds` INTEGER NOT NULL, `exportable` INTEGER NOT NULL, `shareable` INTEGER NOT NULL, `sharing_policy` TEXT NOT NULL, `source` TEXT NOT NULL, `remote_backend` TEXT, `use_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `rp_id` TEXT, `rp_name` TEXT, `user_id` TEXT, `user_name` TEXT, `user_display_name` TEXT, `is_discoverable` INTEGER NOT NULL, `sign_count` INTEGER NOT NULL, `is_system_key` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_keys_key_id` ON `keys` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_key_type` ON `keys` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_algorithm` ON `keys` (`algorithm`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_source` ON `keys` (`source`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_rp_id` ON `keys` (`rp_id`)",
            "CREATE TABLE IF NOT EXISTS `key_sharing_policies` (`key_id` TEXT NOT NULL, `peer_public_key_hex` TEXT NOT NULL, `allowed` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, PRIMARY KEY(`key_id`, `peer_public_key_hex`), FOREIGN KEY(`key_id`) REFERENCES `keys`(`key_id`) ON UPDATE NO ACTION ON DELETE CASCADE )",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_key_id` ON `key_sharing_policies` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_peer_public_key_hex` ON `key_sharing_policies` (`peer_public_key_hex`)",
            "CREATE TABLE IF NOT EXISTS `audit_logs` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `timestamp` INTEGER NOT NULL, `operation_type` TEXT NOT NULL, `key_id` TEXT, `key_label` TEXT, `key_type` TEXT, `device_id` TEXT, `device_name` TEXT, `success` INTEGER NOT NULL, `error_message` TEXT, `details` TEXT, `duration_ms` INTEGER)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_timestamp` ON `audit_logs` (`timestamp`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_operation_type` ON `audit_logs` (`operation_type`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_id` ON `audit_logs` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_type` ON `audit_logs` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_device_id` ON `audit_logs` (`device_id`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_success` ON `audit_logs` (`success`)",
            "CREATE TABLE IF NOT EXISTS `certificates` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `serial_number` TEXT NOT NULL, `subject_dn` TEXT NOT NULL, `issuer_dn` TEXT NOT NULL, `not_before` INTEGER NOT NULL, `not_after` INTEGER NOT NULL, `profile` TEXT NOT NULL, `fingerprint` TEXT NOT NULL, `certificate_pem` TEXT NOT NULL, `chain_pem` TEXT, `key_id` TEXT, `device_id` TEXT, `revoked` INTEGER NOT NULL, `revoked_at` INTEGER, `revoked_reason` INTEGER, `is_ca` INTEGER NOT NULL, `created_at` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_certificates_serial_number` ON `certificates` (`serial_number`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_profile` ON `certificates` (`profile`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_key_id` ON `certificates` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_revoked` ON `certificates` (`revoked`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_not_after` ON `certificates` (`not_after`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_is_ca` ON `certificates` (`is_ca`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_fingerprint` ON `certificates` (`fingerprint`)",
            "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)",
            "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, '8d3f35f57163013998af64083ca5e0d6')"
        ),
        7 to listOf(
            "CREATE TABLE IF NOT EXISTS `credential_metadata` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `credential_id` TEXT NOT NULL, `rp_id` TEXT NOT NULL, `rp_name` TEXT NOT NULL, `user_id` TEXT NOT NULL, `user_name` TEXT NOT NULL, `user_display_name` TEXT NOT NULL, `public_key_cose` BLOB NOT NULL, `sign_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `is_discoverable` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_credential_metadata_credential_id` ON `credential_metadata` (`credential_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_rp_id` ON `credential_metadata` (`rp_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_user_id_rp_id` ON `credential_metadata` (`user_id`, `rp_id`)",
            "CREATE TABLE IF NOT EXISTS `keys` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `key_id` TEXT NOT NULL, `key_type` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `label` TEXT NOT NULL, `public_key_der` BLOB, `public_key_cose` BLOB, `key_size_bits` INTEGER NOT NULL, `strongbox_backed` INTEGER NOT NULL, `biometric_required` INTEGER NOT NULL, `auth_duration_seconds` INTEGER NOT NULL, `exportable` INTEGER NOT NULL, `shareable` INTEGER NOT NULL, `sharing_policy` TEXT NOT NULL, `source` TEXT NOT NULL, `remote_backend` TEXT, `use_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `rp_id` TEXT, `rp_name` TEXT, `user_id` TEXT, `user_name` TEXT, `user_display_name` TEXT, `is_discoverable` INTEGER NOT NULL, `sign_count` INTEGER NOT NULL, `is_system_key` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_keys_key_id` ON `keys` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_key_type` ON `keys` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_algorithm` ON `keys` (`algorithm`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_source` ON `keys` (`source`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_rp_id` ON `keys` (`rp_id`)",
            "CREATE TABLE IF NOT EXISTS `key_sharing_policies` (`key_id` TEXT NOT NULL, `peer_public_key_hex` TEXT NOT NULL, `allowed` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, PRIMARY KEY(`key_id`, `peer_public_key_hex`), FOREIGN KEY(`key_id`) REFERENCES `keys`(`key_id`) ON UPDATE NO ACTION ON DELETE CASCADE )",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_key_id` ON `key_sharing_policies` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_peer_public_key_hex` ON `key_sharing_policies` (`peer_public_key_hex`)",
            "CREATE TABLE IF NOT EXISTS `audit_logs` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `timestamp` INTEGER NOT NULL, `operation_type` TEXT NOT NULL, `key_id` TEXT, `key_label` TEXT, `key_type` TEXT, `device_id` TEXT, `device_name` TEXT, `success` INTEGER NOT NULL, `error_message` TEXT, `details` TEXT, `duration_ms` INTEGER)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_timestamp` ON `audit_logs` (`timestamp`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_operation_type` ON `audit_logs` (`operation_type`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_id` ON `audit_logs` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_type` ON `audit_logs` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_device_id` ON `audit_logs` (`device_id`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_success` ON `audit_logs` (`success`)",
            "CREATE TABLE IF NOT EXISTS `certificates` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `serial_number` TEXT NOT NULL, `subject_dn` TEXT NOT NULL, `issuer_dn` TEXT NOT NULL, `not_before` INTEGER NOT NULL, `not_after` INTEGER NOT NULL, `profile` TEXT NOT NULL, `fingerprint` TEXT NOT NULL, `certificate_pem` TEXT NOT NULL, `chain_pem` TEXT, `key_id` TEXT, `device_id` TEXT, `revoked` INTEGER NOT NULL, `revoked_at` INTEGER, `revoked_reason` INTEGER, `is_ca` INTEGER NOT NULL, `created_at` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_certificates_serial_number` ON `certificates` (`serial_number`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_profile` ON `certificates` (`profile`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_key_id` ON `certificates` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_revoked` ON `certificates` (`revoked`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_not_after` ON `certificates` (`not_after`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_is_ca` ON `certificates` (`is_ca`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_fingerprint` ON `certificates` (`fingerprint`)",
            "CREATE TABLE IF NOT EXISTS `contacts` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `name` TEXT NOT NULL, `public_key_der` BLOB NOT NULL, `public_key_fingerprint` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `imported_at` INTEGER NOT NULL, `source` TEXT NOT NULL, `notes` TEXT)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_contacts_public_key_fingerprint` ON `contacts` (`public_key_fingerprint`)",
            "CREATE INDEX IF NOT EXISTS `index_contacts_name` ON `contacts` (`name`)",
            "CREATE INDEX IF NOT EXISTS `index_contacts_algorithm` ON `contacts` (`algorithm`)",
            "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)",
            "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, 'b8fce9b41800bfc3bcdf026656df2910')"
        ),
        8 to listOf(
            "CREATE TABLE IF NOT EXISTS `credential_metadata` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `credential_id` TEXT NOT NULL, `rp_id` TEXT NOT NULL, `rp_name` TEXT NOT NULL, `user_id` TEXT NOT NULL, `user_name` TEXT NOT NULL, `user_display_name` TEXT NOT NULL, `public_key_cose` BLOB NOT NULL, `sign_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `is_discoverable` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_credential_metadata_credential_id` ON `credential_metadata` (`credential_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_rp_id` ON `credential_metadata` (`rp_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_user_id_rp_id` ON `credential_metadata` (`user_id`, `rp_id`)",
            "CREATE TABLE IF NOT EXISTS `keys` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `key_id` TEXT NOT NULL, `key_type` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `label` TEXT NOT NULL, `public_key_der` BLOB, `public_key_cose` BLOB, `key_size_bits` INTEGER NOT NULL, `strongbox_backed` INTEGER NOT NULL, `biometric_required` INTEGER NOT NULL, `auth_duration_seconds` INTEGER NOT NULL, `exportable` INTEGER NOT NULL, `shareable` INTEGER NOT NULL, `sharing_policy` TEXT NOT NULL, `source` TEXT NOT NULL, `remote_backend` TEXT, `use_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `rp_id` TEXT, `rp_name` TEXT, `user_id` TEXT, `user_name` TEXT, `user_display_name` TEXT, `is_discoverable` INTEGER NOT NULL, `sign_count` INTEGER NOT NULL, `is_system_key` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_keys_key_id` ON `keys` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_key_type` ON `keys` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_algorithm` ON `keys` (`algorithm`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_source` ON `keys` (`source`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_rp_id` ON `keys` (`rp_id`)",
            "CREATE TABLE IF NOT EXISTS `key_sharing_policies` (`key_id` TEXT NOT NULL, `peer_public_key_hex` TEXT NOT NULL, `allowed` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, PRIMARY KEY(`key_id`, `peer_public_key_hex`), FOREIGN KEY(`key_id`) REFERENCES `keys`(`key_id`) ON UPDATE NO ACTION ON DELETE CASCADE )",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_key_id` ON `key_sharing_policies` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_peer_public_key_hex` ON `key_sharing_policies` (`peer_public_key_hex`)",
            "CREATE TABLE IF NOT EXISTS `audit_logs` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `timestamp` INTEGER NOT NULL, `operation_type` TEXT NOT NULL, `key_id` TEXT, `key_label` TEXT, `key_type` TEXT, `device_id` TEXT, `device_name` TEXT, `success` INTEGER NOT NULL, `error_message` TEXT, `details` TEXT, `duration_ms` INTEGER)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_timestamp` ON `audit_logs` (`timestamp`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_operation_type` ON `audit_logs` (`operation_type`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_id` ON `audit_logs` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_type` ON `audit_logs` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_device_id` ON `audit_logs` (`device_id`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_success` ON `audit_logs` (`success`)",
            "CREATE TABLE IF NOT EXISTS `certificates` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `serial_number` TEXT NOT NULL, `subject_dn` TEXT NOT NULL, `issuer_dn` TEXT NOT NULL, `not_before` INTEGER NOT NULL, `not_after` INTEGER NOT NULL, `profile` TEXT NOT NULL, `fingerprint` TEXT NOT NULL, `certificate_pem` TEXT NOT NULL, `chain_pem` TEXT, `key_id` TEXT, `device_id` TEXT, `revoked` INTEGER NOT NULL, `revoked_at` INTEGER, `revoked_reason` INTEGER, `is_ca` INTEGER NOT NULL, `created_at` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_certificates_serial_number` ON `certificates` (`serial_number`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_profile` ON `certificates` (`profile`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_key_id` ON `certificates` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_revoked` ON `certificates` (`revoked`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_not_after` ON `certificates` (`not_after`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_is_ca` ON `certificates` (`is_ca`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_fingerprint` ON `certificates` (`fingerprint`)",
            "CREATE TABLE IF NOT EXISTS `contacts` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `name` TEXT NOT NULL, `public_key_der` BLOB NOT NULL, `public_key_fingerprint` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `imported_at` INTEGER NOT NULL, `source` TEXT NOT NULL, `notes` TEXT)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_contacts_public_key_fingerprint` ON `contacts` (`public_key_fingerprint`)",
            "CREATE INDEX IF NOT EXISTS `index_contacts_name` ON `contacts` (`name`)",
            "CREATE INDEX IF NOT EXISTS `index_contacts_algorithm` ON `contacts` (`algorithm`)",
            "CREATE TABLE IF NOT EXISTS `oath_credentials` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `oath_id` TEXT NOT NULL, `oath_type` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `digits` INTEGER NOT NULL, `period_seconds` INTEGER NOT NULL, `counter` INTEGER NOT NULL, `issuer` TEXT, `account_name` TEXT NOT NULL, `secret_encrypted` BLOB NOT NULL, `source` TEXT NOT NULL, `remote_device_id` TEXT, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER, `use_count` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_oath_credentials_oath_id` ON `oath_credentials` (`oath_id`)",
            "CREATE INDEX IF NOT EXISTS `index_oath_credentials_issuer` ON `oath_credentials` (`issuer`)",
            "CREATE INDEX IF NOT EXISTS `index_oath_credentials_source` ON `oath_credentials` (`source`)",
            "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)",
            "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, '313088ece4540024ab6d2ab971166eb9')"
        ),
        9 to listOf(
            "CREATE TABLE IF NOT EXISTS `credential_metadata` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `credential_id` TEXT NOT NULL, `rp_id` TEXT NOT NULL, `rp_name` TEXT NOT NULL, `user_id` TEXT NOT NULL, `user_name` TEXT NOT NULL, `user_display_name` TEXT NOT NULL, `public_key_cose` BLOB NOT NULL, `sign_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `is_discoverable` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_credential_metadata_credential_id` ON `credential_metadata` (`credential_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_rp_id` ON `credential_metadata` (`rp_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_user_id_rp_id` ON `credential_metadata` (`user_id`, `rp_id`)",
            "CREATE TABLE IF NOT EXISTS `keys` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `key_id` TEXT NOT NULL, `key_type` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `label` TEXT NOT NULL, `public_key_der` BLOB, `public_key_cose` BLOB, `key_size_bits` INTEGER NOT NULL, `strongbox_backed` INTEGER NOT NULL, `biometric_required` INTEGER NOT NULL, `auth_duration_seconds` INTEGER NOT NULL, `exportable` INTEGER NOT NULL, `shareable` INTEGER NOT NULL, `sharing_policy` TEXT NOT NULL, `source` TEXT NOT NULL, `remote_backend` TEXT, `use_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `rp_id` TEXT, `rp_name` TEXT, `user_id` TEXT, `user_name` TEXT, `user_display_name` TEXT, `is_discoverable` INTEGER NOT NULL, `sign_count` INTEGER NOT NULL, `is_system_key` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_keys_key_id` ON `keys` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_key_type` ON `keys` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_algorithm` ON `keys` (`algorithm`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_source` ON `keys` (`source`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_rp_id` ON `keys` (`rp_id`)",
            "CREATE TABLE IF NOT EXISTS `key_sharing_policies` (`key_id` TEXT NOT NULL, `peer_public_key_hex` TEXT NOT NULL, `allowed` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, PRIMARY KEY(`key_id`, `peer_public_key_hex`), FOREIGN KEY(`key_id`) REFERENCES `keys`(`key_id`) ON UPDATE NO ACTION ON DELETE CASCADE )",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_key_id` ON `key_sharing_policies` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_peer_public_key_hex` ON `key_sharing_policies` (`peer_public_key_hex`)",
            "CREATE TABLE IF NOT EXISTS `audit_logs` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `timestamp` INTEGER NOT NULL, `operation_type` TEXT NOT NULL, `key_id` TEXT, `key_label` TEXT, `key_type` TEXT, `device_id` TEXT, `device_name` TEXT, `success` INTEGER NOT NULL, `error_message` TEXT, `details` TEXT, `duration_ms` INTEGER)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_timestamp` ON `audit_logs` (`timestamp`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_operation_type` ON `audit_logs` (`operation_type`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_id` ON `audit_logs` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_type` ON `audit_logs` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_device_id` ON `audit_logs` (`device_id`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_success` ON `audit_logs` (`success`)",
            "CREATE TABLE IF NOT EXISTS `certificates` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `serial_number` TEXT NOT NULL, `subject_dn` TEXT NOT NULL, `issuer_dn` TEXT NOT NULL, `not_before` INTEGER NOT NULL, `not_after` INTEGER NOT NULL, `profile` TEXT NOT NULL, `fingerprint` TEXT NOT NULL, `certificate_pem` TEXT NOT NULL, `chain_pem` TEXT, `key_id` TEXT, `device_id` TEXT, `revoked` INTEGER NOT NULL, `revoked_at` INTEGER, `revoked_reason` INTEGER, `is_ca` INTEGER NOT NULL, `created_at` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_certificates_serial_number` ON `certificates` (`serial_number`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_profile` ON `certificates` (`profile`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_key_id` ON `certificates` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_revoked` ON `certificates` (`revoked`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_not_after` ON `certificates` (`not_after`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_is_ca` ON `certificates` (`is_ca`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_fingerprint` ON `certificates` (`fingerprint`)",
            "CREATE TABLE IF NOT EXISTS `contacts` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `name` TEXT NOT NULL, `public_key_der` BLOB NOT NULL, `public_key_fingerprint` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `imported_at` INTEGER NOT NULL, `source` TEXT NOT NULL, `notes` TEXT)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_contacts_public_key_fingerprint` ON `contacts` (`public_key_fingerprint`)",
            "CREATE INDEX IF NOT EXISTS `index_contacts_name` ON `contacts` (`name`)",
            "CREATE INDEX IF NOT EXISTS `index_contacts_algorithm` ON `contacts` (`algorithm`)",
            "CREATE TABLE IF NOT EXISTS `oath_credentials` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `oath_id` TEXT NOT NULL, `oath_type` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `digits` INTEGER NOT NULL, `period_seconds` INTEGER NOT NULL, `counter` INTEGER NOT NULL, `issuer` TEXT, `account_name` TEXT NOT NULL, `secret_encrypted` BLOB NOT NULL, `source` TEXT NOT NULL, `remote_device_id` TEXT, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER, `use_count` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_oath_credentials_oath_id` ON `oath_credentials` (`oath_id`)",
            "CREATE INDEX IF NOT EXISTS `index_oath_credentials_issuer` ON `oath_credentials` (`issuer`)",
            "CREATE INDEX IF NOT EXISTS `index_oath_credentials_source` ON `oath_credentials` (`source`)",
            "CREATE TABLE IF NOT EXISTS `piv_slots` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `slot_id` TEXT NOT NULL, `algorithm` TEXT, `public_key_der` BLOB, `certificate_der` BLOB, `has_key` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER, `use_count` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_piv_slots_slot_id` ON `piv_slots` (`slot_id`)",
            "CREATE INDEX IF NOT EXISTS `index_piv_slots_has_key` ON `piv_slots` (`has_key`)",
            "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)",
            "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, '58854153aba5ea2f9db3277db71a1ae9')"
        ),
        10 to listOf(
            "CREATE TABLE IF NOT EXISTS `credential_metadata` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `credential_id` TEXT NOT NULL, `rp_id` TEXT NOT NULL, `rp_name` TEXT NOT NULL, `user_id` TEXT NOT NULL, `user_name` TEXT NOT NULL, `user_display_name` TEXT NOT NULL, `public_key_cose` BLOB NOT NULL, `sign_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `is_discoverable` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_credential_metadata_credential_id` ON `credential_metadata` (`credential_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_rp_id` ON `credential_metadata` (`rp_id`)",
            "CREATE INDEX IF NOT EXISTS `index_credential_metadata_user_id_rp_id` ON `credential_metadata` (`user_id`, `rp_id`)",
            "CREATE TABLE IF NOT EXISTS `keys` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `key_id` TEXT NOT NULL, `key_type` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `label` TEXT NOT NULL, `public_key_der` BLOB, `public_key_cose` BLOB, `key_size_bits` INTEGER NOT NULL, `strongbox_backed` INTEGER NOT NULL, `biometric_required` INTEGER NOT NULL, `auth_duration_seconds` INTEGER NOT NULL, `exportable` INTEGER NOT NULL, `shareable` INTEGER NOT NULL, `sharing_policy` TEXT NOT NULL, `source` TEXT NOT NULL, `remote_backend` TEXT, `use_count` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER NOT NULL, `rp_id` TEXT, `rp_name` TEXT, `user_id` TEXT, `user_name` TEXT, `user_display_name` TEXT, `is_discoverable` INTEGER NOT NULL, `sign_count` INTEGER NOT NULL, `is_system_key` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_keys_key_id` ON `keys` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_key_type` ON `keys` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_algorithm` ON `keys` (`algorithm`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_source` ON `keys` (`source`)",
            "CREATE INDEX IF NOT EXISTS `index_keys_rp_id` ON `keys` (`rp_id`)",
            "CREATE TABLE IF NOT EXISTS `key_sharing_policies` (`key_id` TEXT NOT NULL, `peer_public_key_hex` TEXT NOT NULL, `allowed` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, PRIMARY KEY(`key_id`, `peer_public_key_hex`), FOREIGN KEY(`key_id`) REFERENCES `keys`(`key_id`) ON UPDATE NO ACTION ON DELETE CASCADE )",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_key_id` ON `key_sharing_policies` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_key_sharing_policies_peer_public_key_hex` ON `key_sharing_policies` (`peer_public_key_hex`)",
            "CREATE TABLE IF NOT EXISTS `audit_logs` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `timestamp` INTEGER NOT NULL, `operation_type` TEXT NOT NULL, `key_id` TEXT, `key_label` TEXT, `key_type` TEXT, `device_id` TEXT, `device_name` TEXT, `success` INTEGER NOT NULL, `error_message` TEXT, `details` TEXT, `duration_ms` INTEGER)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_timestamp` ON `audit_logs` (`timestamp`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_operation_type` ON `audit_logs` (`operation_type`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_id` ON `audit_logs` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_key_type` ON `audit_logs` (`key_type`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_device_id` ON `audit_logs` (`device_id`)",
            "CREATE INDEX IF NOT EXISTS `index_audit_logs_success` ON `audit_logs` (`success`)",
            "CREATE TABLE IF NOT EXISTS `certificates` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `serial_number` TEXT NOT NULL, `subject_dn` TEXT NOT NULL, `issuer_dn` TEXT NOT NULL, `not_before` INTEGER NOT NULL, `not_after` INTEGER NOT NULL, `profile` TEXT NOT NULL, `fingerprint` TEXT NOT NULL, `certificate_pem` TEXT NOT NULL, `chain_pem` TEXT, `key_id` TEXT, `device_id` TEXT, `revoked` INTEGER NOT NULL, `revoked_at` INTEGER, `revoked_reason` INTEGER, `is_ca` INTEGER NOT NULL, `created_at` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_certificates_serial_number` ON `certificates` (`serial_number`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_profile` ON `certificates` (`profile`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_key_id` ON `certificates` (`key_id`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_revoked` ON `certificates` (`revoked`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_not_after` ON `certificates` (`not_after`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_is_ca` ON `certificates` (`is_ca`)",
            "CREATE INDEX IF NOT EXISTS `index_certificates_fingerprint` ON `certificates` (`fingerprint`)",
            "CREATE TABLE IF NOT EXISTS `contacts` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `name` TEXT NOT NULL, `public_key_der` BLOB NOT NULL, `public_key_fingerprint` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `imported_at` INTEGER NOT NULL, `source` TEXT NOT NULL, `notes` TEXT)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_contacts_public_key_fingerprint` ON `contacts` (`public_key_fingerprint`)",
            "CREATE INDEX IF NOT EXISTS `index_contacts_name` ON `contacts` (`name`)",
            "CREATE INDEX IF NOT EXISTS `index_contacts_algorithm` ON `contacts` (`algorithm`)",
            "CREATE TABLE IF NOT EXISTS `oath_credentials` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `oath_id` TEXT NOT NULL, `oath_type` TEXT NOT NULL, `algorithm` TEXT NOT NULL, `digits` INTEGER NOT NULL, `period_seconds` INTEGER NOT NULL, `counter` INTEGER NOT NULL, `issuer` TEXT, `account_name` TEXT NOT NULL, `secret_encrypted` BLOB NOT NULL, `source` TEXT NOT NULL, `remote_device_id` TEXT, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER, `use_count` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_oath_credentials_oath_id` ON `oath_credentials` (`oath_id`)",
            "CREATE INDEX IF NOT EXISTS `index_oath_credentials_issuer` ON `oath_credentials` (`issuer`)",
            "CREATE INDEX IF NOT EXISTS `index_oath_credentials_source` ON `oath_credentials` (`source`)",
            "CREATE TABLE IF NOT EXISTS `piv_slots` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `slot_id` TEXT NOT NULL, `algorithm` TEXT, `public_key_der` BLOB, `certificate_der` BLOB, `has_key` INTEGER NOT NULL, `created_at` INTEGER NOT NULL, `last_used_at` INTEGER, `use_count` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_piv_slots_slot_id` ON `piv_slots` (`slot_id`)",
            "CREATE INDEX IF NOT EXISTS `index_piv_slots_has_key` ON `piv_slots` (`has_key`)",
            "CREATE TABLE IF NOT EXISTS `passwords` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `password_id` TEXT NOT NULL, `name` TEXT NOT NULL, `title` TEXT, `username` TEXT, `password_encrypted` BLOB NOT NULL, `url` TEXT, `notes` TEXT, `folder_path` TEXT, `source` TEXT NOT NULL, `created_at` INTEGER NOT NULL, `updated_at` INTEGER NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_passwords_password_id` ON `passwords` (`password_id`)",
            "CREATE INDEX IF NOT EXISTS `index_passwords_name` ON `passwords` (`name`)",
            "CREATE INDEX IF NOT EXISTS `index_passwords_source` ON `passwords` (`source`)",
            "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)",
            "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, '14aec21fe86e3f39f29d271ea3c80b4d')"
        )
    ).let {
        // Migration 10->11 rewrites data only, so schema 11 is schema 10 verbatim
        // (11.json differs from 10.json in its version number alone).
        it + (11 to it.getValue(10))
    }
}
