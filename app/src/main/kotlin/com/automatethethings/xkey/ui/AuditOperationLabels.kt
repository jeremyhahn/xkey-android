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
package com.automatethethings.xkey.ui

import androidx.annotation.StringRes
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditOperationType

/**
 * The display label of each audit operation type, shared by the audit screen
 * and the home screen's recent activity.
 */
object AuditOperationLabels {

    @StringRes
    fun labelRes(type: AuditOperationType): Int = when (type) {
        AuditOperationType.KEY_CREATED -> R.string.audit_log_op_key_created
        AuditOperationType.KEY_DELETED -> R.string.audit_log_op_key_deleted
        AuditOperationType.KEY_USED -> R.string.audit_log_op_key_used
        AuditOperationType.KEY_ATTESTED -> R.string.audit_log_op_key_attested
        AuditOperationType.KEY_SHARING_CHANGED -> R.string.audit_log_op_sharing_changed
        AuditOperationType.KEY_EXPORTED -> R.string.audit_log_op_exported
        AuditOperationType.SIGNING_REQUEST -> R.string.audit_log_op_signing
        AuditOperationType.ENCRYPTION_REQUEST -> R.string.audit_log_op_encryption
        AuditOperationType.DECRYPTION_REQUEST -> R.string.audit_log_op_decryption
        AuditOperationType.KEY_DERIVATION_REQUEST -> R.string.audit_log_op_derivation
        AuditOperationType.HMAC_REQUEST -> R.string.audit_log_op_hmac
        AuditOperationType.FIDO2_REGISTRATION -> R.string.audit_log_op_fido2_reg
        AuditOperationType.FIDO2_AUTHENTICATION -> R.string.audit_log_op_fido2
        AuditOperationType.PAIRING_APPROVED -> R.string.audit_log_op_pairing
        AuditOperationType.PAIRING_DENIED -> R.string.audit_log_op_pairing_denied
        AuditOperationType.DEVICE_UNPAIRED -> R.string.audit_log_op_unpaired
        AuditOperationType.CONNECTION_ESTABLISHED -> R.string.audit_log_op_connection
        AuditOperationType.CONNECTION_CLOSED -> R.string.audit_log_op_disconnection
        AuditOperationType.DEVICE_ATTESTED -> R.string.audit_log_op_device_attested
        AuditOperationType.DEVICE_ENROLLED -> R.string.audit_log_op_device_enrolled
        AuditOperationType.SETTINGS_CHANGED -> R.string.audit_log_op_settings
        AuditOperationType.TRUST_STORE_IMPORT -> R.string.audit_log_op_trust_import
        AuditOperationType.TRUST_STORE_DELETE -> R.string.audit_log_op_trust_delete
        AuditOperationType.BIOMETRIC_SUCCESS -> R.string.audit_log_op_biometric_ok
        AuditOperationType.BIOMETRIC_FAILURE -> R.string.audit_log_op_biometric_fail
        AuditOperationType.POLICY_DENIED -> R.string.audit_log_op_policy_denied
        AuditOperationType.SERVICE_STARTED -> R.string.audit_log_op_service_started
        AuditOperationType.SERVICE_STOPPED -> R.string.audit_log_op_service_stopped
        AuditOperationType.CERTIFICATE_ISSUED -> R.string.audit_log_op_cert_issued
        AuditOperationType.CERTIFICATE_REVOKED -> R.string.audit_log_op_cert_revoked
        AuditOperationType.CSR_SIGNED -> R.string.audit_log_op_csr_signed
        AuditOperationType.CRL_GENERATED -> R.string.audit_log_op_crl_generated
        AuditOperationType.CERTIFICATE_EXPORTED -> R.string.audit_log_op_cert_exported
        AuditOperationType.FILE_SIGNED -> R.string.audit_log_op_file_signed
        AuditOperationType.FILE_VERIFIED -> R.string.audit_log_op_file_verified
        AuditOperationType.FILE_ENCRYPTED -> R.string.audit_log_op_file_encrypted
        AuditOperationType.FILE_DECRYPTED -> R.string.audit_log_op_file_decrypted
        AuditOperationType.MEDIA_AUTO_SIGNED -> R.string.audit_log_op_media_auto_signed
        AuditOperationType.CONTACT_IMPORTED -> R.string.audit_log_op_contact_imported
        AuditOperationType.CONTACT_DELETED -> R.string.audit_log_op_contact_deleted
        AuditOperationType.OATH_CREDENTIAL_CREATED -> R.string.audit_log_op_oath_created
        AuditOperationType.OATH_CREDENTIAL_DELETED -> R.string.audit_log_op_oath_deleted
        AuditOperationType.OATH_CODE_GENERATED -> R.string.audit_log_op_oath_code
        AuditOperationType.OATH_SYNC_PERFORMED -> R.string.audit_log_op_oath_sync
        AuditOperationType.COSIGN_INITIATED -> R.string.audit_log_op_cosign_initiated
        AuditOperationType.COSIGN_RECEIVED -> R.string.audit_log_op_cosign_received
        AuditOperationType.PIN_SO_SET -> R.string.audit_log_op_pin_so_set
        AuditOperationType.PIN_SO_CHANGED -> R.string.audit_log_op_pin_so_changed
        AuditOperationType.PIN_USER_SET -> R.string.audit_log_op_pin_user_set
        AuditOperationType.PIN_USER_CHANGED -> R.string.audit_log_op_pin_user_changed
        AuditOperationType.PIN_VERIFICATION_SUCCESS -> R.string.audit_log_op_pin_verify_ok
        AuditOperationType.PIN_VERIFICATION_FAILED -> R.string.audit_log_op_pin_verify_fail
        AuditOperationType.PIN_LOCKOUT_TRIGGERED -> R.string.audit_log_op_pin_lockout
        AuditOperationType.PIN_LOCKOUT_RESET -> R.string.audit_log_op_pin_lockout_reset
        AuditOperationType.PIV_KEY_GENERATED -> R.string.audit_log_op_piv_key_generated
        AuditOperationType.PIV_CERT_IMPORTED -> R.string.audit_log_op_piv_cert_imported
        AuditOperationType.PIV_SIGN_REQUEST -> R.string.audit_log_op_piv_sign_request
        AuditOperationType.PIV_KEY_DELETED -> R.string.audit_log_op_piv_key_deleted
        AuditOperationType.BACKUP_CREATED -> R.string.audit_log_op_backup_created
        AuditOperationType.BACKUP_RESTORED -> R.string.audit_log_op_backup_restored
    }

    /** The operation types the audit screen offers as filter chips, in order. */
    val filterTypes: List<AuditOperationType> = listOf(
        AuditOperationType.KEY_CREATED,
        AuditOperationType.KEY_DELETED,
        AuditOperationType.SIGNING_REQUEST,
        AuditOperationType.FIDO2_AUTHENTICATION,
        AuditOperationType.PAIRING_APPROVED,
        AuditOperationType.CONNECTION_ESTABLISHED
    )
}
