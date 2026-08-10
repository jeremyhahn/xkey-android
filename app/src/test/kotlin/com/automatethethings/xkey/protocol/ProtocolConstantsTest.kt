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
package com.automatethethings.xkey.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Contract tests for the string and integer constants in `Messages.kt`:
 * [MethodNames], [KeyTypes], [ExportFormats] and [ErrorCodes].
 *
 * Every one of these values is a literal that goes on the wire. The desktop
 * side (`go-xkms/xkey/pkg/pairing`) has its own independent copies -- Android
 * re-implements the protocol rather than importing it -- so a typo or a rename
 * here is invisible to the compiler and only shows up as a "method not found"
 * at pairing time. These tests pin the exact spellings, the `local.` / `remote.`
 * namespacing rules, the camelCase convention, and the uniqueness of both the
 * method names and the error codes.
 *
 * The PIV and PIN subsets are covered separately by `PivHandlerTest`; this file
 * covers the remaining families.
 */
class ProtocolConstantsTest {

    /** Every method name Android knows about, for cross-cutting assertions. */
    private val allMethodNames = listOf(
        MethodNames.GENERATE_KEY, MethodNames.SIGN, MethodNames.DELETE_KEY, MethodNames.LOAD_KEY,
        MethodNames.GET_INFO, MethodNames.PING, MethodNames.LIST_KEYS,
        MethodNames.LOCAL_GENERATE_KEY, MethodNames.LOCAL_SIGN, MethodNames.LOCAL_DECRYPT,
        MethodNames.LOCAL_SYMMETRIC_ENCRYPT, MethodNames.LOCAL_SYMMETRIC_DECRYPT, MethodNames.LOCAL_HMAC,
        MethodNames.LOCAL_ECDH, MethodNames.LOCAL_GET_PUBLIC_KEY, MethodNames.LOCAL_LIST_KEYS,
        MethodNames.LOCAL_GET_KEY_INFO, MethodNames.LOCAL_DELETE_KEY, MethodNames.LOCAL_SET_KEY_POLICY,
        MethodNames.LOCAL_ATTEST_KEY, MethodNames.LOCAL_ATTEST_DEVICE, MethodNames.LOCAL_GET_CAPABILITIES,
        MethodNames.LOCAL_LIST_FIDO2_CREDENTIALS, MethodNames.LOCAL_SIGN_FIDO2_ASSERTION,
        MethodNames.REMOTE_LIST_BACKENDS, MethodNames.REMOTE_LIST_KEYS, MethodNames.REMOTE_GET_PUBLIC_KEY,
        MethodNames.REMOTE_SIGN, MethodNames.REMOTE_VERIFY, MethodNames.REMOTE_ENCRYPT,
        MethodNames.REMOTE_DECRYPT, MethodNames.REMOTE_DERIVE_KEY, MethodNames.REMOTE_GENERATE_KEY,
        MethodNames.REMOTE_GET_KEY_INFO, MethodNames.REMOTE_DELETE_KEY, MethodNames.REMOTE_ATTEST_KEY,
        MethodNames.REMOTE_ATTEST_DEVICE,
        MethodNames.PAIRING_CONFIRM, MethodNames.LOCAL_BIOMETRIC_PENDING,
        MethodNames.LOCAL_GET_CA_BUNDLE, MethodNames.LOCAL_GET_IDEVID_CERTIFICATE,
        MethodNames.LOCAL_REQUEST_IDEVID_ISSUANCE, MethodNames.LOCAL_GENERATE_IDEVID_CSR,
        MethodNames.LOCAL_STORE_IDEVID_CERTIFICATE,
        MethodNames.LOCAL_GET_TCG_CSR_IDEVID, MethodNames.LOCAL_ACTIVATE_CREDENTIAL,
        MethodNames.LOCAL_GET_ATTESTATION_QUOTE, MethodNames.LOCAL_GET_IAK_PUBLIC_KEY,
        MethodNames.LOCAL_STORE_ENROLLMENT_CERTS,
        MethodNames.LOCAL_OATH_LIST, MethodNames.LOCAL_OATH_GENERATE, MethodNames.LOCAL_OATH_ADD,
        MethodNames.LOCAL_OATH_REMOVE, MethodNames.REMOTE_OATH_ADD, MethodNames.REMOTE_OATH_GENERATE,
        MethodNames.LOCAL_SYNC_TRUST_STORE, MethodNames.LOCAL_SYNC_OATH, MethodNames.LOCAL_SYNC_PASSWORDS,
        MethodNames.LOCAL_SYNC_STATUS, MethodNames.REMOTE_SYNC_TRUST_STORE, MethodNames.REMOTE_SYNC_OATH,
        MethodNames.REMOTE_SYNC_PASSWORDS, MethodNames.REMOTE_SYNC_ALL, MethodNames.REMOTE_SYNC_STATUS,
        MethodNames.LOCAL_CREATE_BACKUP, MethodNames.LOCAL_RESTORE_BACKUP, MethodNames.REMOTE_CREATE_BACKUP,
        MethodNames.REMOTE_RESTORE_BACKUP, MethodNames.REMOTE_LIST_BACKUPS,
        MethodNames.LOCAL_SHARE_PUBLIC_KEY, MethodNames.LOCAL_SHARE_SYMMETRIC,
        MethodNames.LOCAL_IMPORT_SHARED_KEY, MethodNames.REMOTE_SHARE_PUBLIC_KEY,
        MethodNames.REMOTE_SHARE_SYMMETRIC, MethodNames.REMOTE_IMPORT_SHARED_KEY,
        MethodNames.COSIGN_REQUEST, MethodNames.COSIGN_RESPONSE,
        MethodNames.LOCAL_PIN_VERIFY, MethodNames.LOCAL_PIN_STATUS, MethodNames.LOCAL_PIN_SET,
        MethodNames.LOCAL_PIN_CHANGE, MethodNames.LOCAL_PIN_RESET_LOCKOUT,
        MethodNames.LOCAL_PIV_GENERATE_KEY, MethodNames.LOCAL_PIV_IMPORT_CERT,
        MethodNames.LOCAL_PIV_LIST_SLOTS, MethodNames.LOCAL_PIV_SIGN, MethodNames.LOCAL_PIV_GET_CERT,
        MethodNames.REMOTE_PIV_LIST_SLOTS, MethodNames.REMOTE_PIV_SIGN, MethodNames.REMOTE_PIV_GET_CERT
    )

    /**
     * Every declared error code, read from [ErrorCodes] rather than listed here.
     *
     * A hand-maintained list is why `every error code is unique` passed while
     * FEATURE_UNAVAILABLE and PIV_SLOT_NOT_FOUND were both -32026: the new
     * constant was simply never added, so the assertion guarded a list rather
     * than the enum. Reading the fields means a code that is declared is
     * checked, whether or not anyone remembers this file.
     *
     * `const val Int` compiles to a static final int, so the fields are
     * reachable; INSTANCE and any synthetic members are filtered out by type.
     */
    private val allErrorCodes: List<Int> = ErrorCodes::class.java.declaredFields
        .filter { it.type == Int::class.javaPrimitiveType }
        .map { field ->
            field.isAccessible = true
            field.getInt(null)
        }

    /** The same codes with their names, so a failure says which collided. */
    private val errorCodesByName: List<Pair<String, Int>> =
        ErrorCodes::class.java.declaredFields
            .filter { it.type == Int::class.javaPrimitiveType }
            .map { field ->
                field.isAccessible = true
                field.name to field.getInt(null)
            }

    @Test
    fun `the reflective error code list actually found the constants`() {
        // Guards the guard: if the reflection ever returns nothing, every
        // assertion built on it would pass vacuously.
        assertTrue(
            "expected to discover the declared error codes, found ${allErrorCodes.size}",
            allErrorCodes.size >= 30
        )
        assertTrue(
            "FEATURE_UNAVAILABLE must be discovered",
            errorCodesByName.any { it.first == "FEATURE_UNAVAILABLE" }
        )
    }

    // -------------------------------------------------------------------------
    // Base (un-namespaced) methods
    // -------------------------------------------------------------------------

    @Test
    fun `base method names are un-namespaced and match the go-xkms spelling`() {
        assertEquals("generateKey", MethodNames.GENERATE_KEY)
        assertEquals("sign", MethodNames.SIGN)
        assertEquals("deleteKey", MethodNames.DELETE_KEY)
        assertEquals("loadKey", MethodNames.LOAD_KEY)
        assertEquals("getInfo", MethodNames.GET_INFO)
        assertEquals("ping", MethodNames.PING)
        assertEquals("listKeys", MethodNames.LIST_KEYS)
    }

    // -------------------------------------------------------------------------
    // local.* crypto and key management
    // -------------------------------------------------------------------------

    @Test
    fun `local crypto method names match the go-xkms spelling`() {
        assertEquals("local.generateKey", MethodNames.LOCAL_GENERATE_KEY)
        assertEquals("local.sign", MethodNames.LOCAL_SIGN)
        assertEquals("local.decrypt", MethodNames.LOCAL_DECRYPT)
        assertEquals("local.symmetricEncrypt", MethodNames.LOCAL_SYMMETRIC_ENCRYPT)
        assertEquals("local.symmetricDecrypt", MethodNames.LOCAL_SYMMETRIC_DECRYPT)
        assertEquals("local.hmac", MethodNames.LOCAL_HMAC)
        assertEquals("local.ecdh", MethodNames.LOCAL_ECDH)
    }

    @Test
    fun `local key management method names match the go-xkms spelling`() {
        assertEquals("local.getPublicKey", MethodNames.LOCAL_GET_PUBLIC_KEY)
        assertEquals("local.listKeys", MethodNames.LOCAL_LIST_KEYS)
        assertEquals("local.getKeyInfo", MethodNames.LOCAL_GET_KEY_INFO)
        assertEquals("local.deleteKey", MethodNames.LOCAL_DELETE_KEY)
        assertEquals("local.setKeyPolicy", MethodNames.LOCAL_SET_KEY_POLICY)
        assertEquals("local.attestKey", MethodNames.LOCAL_ATTEST_KEY)
        assertEquals("local.attestDevice", MethodNames.LOCAL_ATTEST_DEVICE)
        assertEquals("local.getCapabilities", MethodNames.LOCAL_GET_CAPABILITIES)
    }

    @Test
    fun `local FIDO2 method names match the go-xkms spelling`() {
        assertEquals("local.listFido2Credentials", MethodNames.LOCAL_LIST_FIDO2_CREDENTIALS)
        assertEquals("local.signFido2Assertion", MethodNames.LOCAL_SIGN_FIDO2_ASSERTION)
    }

    // -------------------------------------------------------------------------
    // remote.* bridge methods
    // -------------------------------------------------------------------------

    @Test
    fun `remote bridge method names match the go-xkms spelling`() {
        assertEquals("remote.listBackends", MethodNames.REMOTE_LIST_BACKENDS)
        assertEquals("remote.listKeys", MethodNames.REMOTE_LIST_KEYS)
        assertEquals("remote.getPublicKey", MethodNames.REMOTE_GET_PUBLIC_KEY)
        assertEquals("remote.sign", MethodNames.REMOTE_SIGN)
        assertEquals("remote.verify", MethodNames.REMOTE_VERIFY)
        assertEquals("remote.encrypt", MethodNames.REMOTE_ENCRYPT)
        assertEquals("remote.decrypt", MethodNames.REMOTE_DECRYPT)
        assertEquals("remote.deriveKey", MethodNames.REMOTE_DERIVE_KEY)
        assertEquals("remote.generateKey", MethodNames.REMOTE_GENERATE_KEY)
        assertEquals("remote.getKeyInfo", MethodNames.REMOTE_GET_KEY_INFO)
        assertEquals("remote.deleteKey", MethodNames.REMOTE_DELETE_KEY)
        assertEquals("remote.attestKey", MethodNames.REMOTE_ATTEST_KEY)
        assertEquals("remote.attestDevice", MethodNames.REMOTE_ATTEST_DEVICE)
    }

    // -------------------------------------------------------------------------
    // OATH, sync, backup and sharing families
    // -------------------------------------------------------------------------

    @Test
    fun `OATH method names match the go-xkms spelling on both sides of the link`() {
        assertEquals("local.oathList", MethodNames.LOCAL_OATH_LIST)
        assertEquals("local.oathGenerate", MethodNames.LOCAL_OATH_GENERATE)
        assertEquals("local.oathAdd", MethodNames.LOCAL_OATH_ADD)
        assertEquals("local.oathRemove", MethodNames.LOCAL_OATH_REMOVE)
        assertEquals("remote.oathAdd", MethodNames.REMOTE_OATH_ADD)
        assertEquals("remote.oathGenerate", MethodNames.REMOTE_OATH_GENERATE)
    }

    @Test
    fun `sync method names match the go-xkms spelling`() {
        assertEquals("local.syncTrustStore", MethodNames.LOCAL_SYNC_TRUST_STORE)
        assertEquals("local.syncOATH", MethodNames.LOCAL_SYNC_OATH)
        assertEquals("local.syncPasswords", MethodNames.LOCAL_SYNC_PASSWORDS)
        assertEquals("local.syncStatus", MethodNames.LOCAL_SYNC_STATUS)
        assertEquals("remote.syncTrustStore", MethodNames.REMOTE_SYNC_TRUST_STORE)
        assertEquals("remote.syncOATH", MethodNames.REMOTE_SYNC_OATH)
        assertEquals("remote.syncPasswords", MethodNames.REMOTE_SYNC_PASSWORDS)
        assertEquals("remote.syncAll", MethodNames.REMOTE_SYNC_ALL)
        assertEquals("remote.syncStatus", MethodNames.REMOTE_SYNC_STATUS)
    }

    @Test
    fun `backup method names match the go-xkms spelling`() {
        assertEquals("local.createBackup", MethodNames.LOCAL_CREATE_BACKUP)
        assertEquals("local.restoreBackup", MethodNames.LOCAL_RESTORE_BACKUP)
        assertEquals("remote.createBackup", MethodNames.REMOTE_CREATE_BACKUP)
        assertEquals("remote.restoreBackup", MethodNames.REMOTE_RESTORE_BACKUP)
        assertEquals("remote.listBackups", MethodNames.REMOTE_LIST_BACKUPS)
    }

    @Test
    fun `key sharing method names match the go-xkms spelling`() {
        assertEquals("local.sharePublicKey", MethodNames.LOCAL_SHARE_PUBLIC_KEY)
        assertEquals("local.shareSymmetric", MethodNames.LOCAL_SHARE_SYMMETRIC)
        assertEquals("local.importSharedKey", MethodNames.LOCAL_IMPORT_SHARED_KEY)
        assertEquals("remote.sharePublicKey", MethodNames.REMOTE_SHARE_PUBLIC_KEY)
        assertEquals("remote.shareSymmetric", MethodNames.REMOTE_SHARE_SYMMETRIC)
        assertEquals("remote.importSharedKey", MethodNames.REMOTE_IMPORT_SHARED_KEY)
    }

    // -------------------------------------------------------------------------
    // IDevID and TCG enrollment families
    // -------------------------------------------------------------------------

    @Test
    fun `IDevID exchange method names match the go-xkms spelling`() {
        assertEquals("local.getCABundle", MethodNames.LOCAL_GET_CA_BUNDLE)
        assertEquals("local.getIDevIDCertificate", MethodNames.LOCAL_GET_IDEVID_CERTIFICATE)
        assertEquals("local.requestIDevIDIssuance", MethodNames.LOCAL_REQUEST_IDEVID_ISSUANCE)
        assertEquals("local.generateIDevIDCSR", MethodNames.LOCAL_GENERATE_IDEVID_CSR)
        assertEquals("local.storeIDevIDCertificate", MethodNames.LOCAL_STORE_IDEVID_CERTIFICATE)
    }

    @Test
    fun `TCG enrollment method names match the go-xkms spelling`() {
        assertEquals("local.getTCGCSRIDevID", MethodNames.LOCAL_GET_TCG_CSR_IDEVID)
        assertEquals("local.activateCredential", MethodNames.LOCAL_ACTIVATE_CREDENTIAL)
        assertEquals("local.getAttestationQuote", MethodNames.LOCAL_GET_ATTESTATION_QUOTE)
        assertEquals("local.getIAKPublicKey", MethodNames.LOCAL_GET_IAK_PUBLIC_KEY)
        assertEquals("local.storeEnrollmentCerts", MethodNames.LOCAL_STORE_ENROLLMENT_CERTS)
    }

    // -------------------------------------------------------------------------
    // Pairing, notification and co-signing
    // -------------------------------------------------------------------------

    @Test
    fun `pairing and notification method names match the go-xkms spelling`() {
        assertEquals("pairing.confirm", MethodNames.PAIRING_CONFIRM)
        assertEquals("local.biometricPending", MethodNames.LOCAL_BIOMETRIC_PENDING)
    }

    @Test
    fun `co-signing method names use the cosign namespace`() {
        assertEquals("cosign.request", MethodNames.COSIGN_REQUEST)
        assertEquals("cosign.response", MethodNames.COSIGN_RESPONSE)
    }

    // -------------------------------------------------------------------------
    // Cross-cutting method name rules
    // -------------------------------------------------------------------------

    @Test
    fun `every method name is unique`() {
        val duplicates = allMethodNames.groupBy { it }.filterValues { it.size > 1 }.keys

        assertTrue("duplicate method names: $duplicates", duplicates.isEmpty())
    }

    @Test
    fun `every namespaced method name uses a known namespace`() {
        val namespaced = allMethodNames.filter { it.contains('.') }

        namespaced.forEach { name ->
            val namespace = name.substringBefore('.')
            assertTrue(
                "method '$name' uses an unexpected namespace '$namespace'",
                namespace in setOf("local", "remote", "pairing", "cosign")
            )
        }
    }

    @Test
    fun `every method name uses a lowercase-initial camelCase local part`() {
        allMethodNames.forEach { name ->
            val localPart = name.substringAfter('.')
            assertTrue("method '$name' must not contain an underscore", !localPart.contains('_'))
            assertTrue("method '$name' must not contain a space", !localPart.contains(' '))
            assertTrue(
                "method '$name' local part must start lowercase",
                localPart.first().isLowerCase()
            )
        }
    }

    @Test
    fun `no method name has leading or trailing whitespace`() {
        allMethodNames.forEach { name ->
            assertEquals("method name '$name' must be trimmed", name, name.trim())
        }
    }

    // -------------------------------------------------------------------------
    // KeyTypes
    // -------------------------------------------------------------------------

    @Test
    fun `key type constants have the expected lowercase values`() {
        assertEquals("fido2", KeyTypes.FIDO2)
        assertEquals("tls", KeyTypes.TLS)
        assertEquals("signing", KeyTypes.SIGNING)
        assertEquals("encryption", KeyTypes.ENCRYPTION)
        assertEquals("secret", KeyTypes.SECRET)
        assertEquals("hmac", KeyTypes.HMAC)
        assertEquals("ca", KeyTypes.CA)
        assertEquals("attestation", KeyTypes.ATTESTATION)
    }

    @Test
    fun `key type constants are unique and lowercase`() {
        val types = listOf(
            KeyTypes.FIDO2, KeyTypes.TLS, KeyTypes.SIGNING, KeyTypes.ENCRYPTION,
            KeyTypes.SECRET, KeyTypes.HMAC, KeyTypes.CA, KeyTypes.ATTESTATION
        )

        assertEquals("key types must be unique", types.size, types.toSet().size)
        types.forEach { assertEquals("key type '$it' must be lowercase", it.lowercase(), it) }
    }

    // -------------------------------------------------------------------------
    // ExportFormats
    // -------------------------------------------------------------------------

    @Test
    fun `export format constants have the expected lowercase values`() {
        assertEquals("der", ExportFormats.DER)
        assertEquals("pem", ExportFormats.PEM)
        assertEquals("ssh", ExportFormats.SSH)
        assertEquals("cose", ExportFormats.COSE)
    }

    @Test
    fun `export format constants are unique`() {
        val formats = listOf(ExportFormats.DER, ExportFormats.PEM, ExportFormats.SSH, ExportFormats.COSE)

        assertEquals("export formats must be unique", formats.size, formats.toSet().size)
    }

    @Test
    fun `the default export format is DER`() {
        assertEquals(ExportFormats.DER, LocalGetPublicKeyParams(keyId = "k").format)
    }

    // -------------------------------------------------------------------------
    // ErrorCodes
    // -------------------------------------------------------------------------

    @Test
    fun `xKey specific error codes have the expected values`() {
        assertEquals(-32001, ErrorCodes.KEY_NOT_FOUND)
        assertEquals(-32002, ErrorCodes.USER_CANCELLED)
        assertEquals(-32003, ErrorCodes.BIOMETRIC_FAILED)
        assertEquals(-32004, ErrorCodes.BIOMETRIC_NOT_ENROLLED)
        assertEquals(-32005, ErrorCodes.BIOMETRIC_LOCKOUT)
        assertEquals(-32006, ErrorCodes.KEY_GENERATION_FAILED)
        assertEquals(-32007, ErrorCodes.SIGNING_FAILED)
        assertEquals(-32008, ErrorCodes.ENCRYPTION_FAILED)
        assertEquals(-32009, ErrorCodes.DECRYPTION_FAILED)
        assertEquals(-32010, ErrorCodes.INVALID_ALGORITHM)
        assertEquals(-32011, ErrorCodes.STRONGBOX_UNAVAILABLE)
        assertEquals(-32012, ErrorCodes.SESSION_EXPIRED)
        assertEquals(-32013, ErrorCodes.RATE_LIMITED)
        assertEquals(-32014, ErrorCodes.HMAC_FAILED)
        assertEquals(-32015, ErrorCodes.ECDH_FAILED)
        assertEquals(-32016, ErrorCodes.EXPORT_FAILED)
        assertEquals(-32017, ErrorCodes.PAIRING_REJECTED)
        assertEquals(-32018, ErrorCodes.BACKEND_DENIED)
        assertEquals(-32019, ErrorCodes.OPERATION_DENIED)
        assertEquals(-32020, ErrorCodes.STORAGE_FULL)
        assertEquals(-32021, ErrorCodes.KEY_EXISTS)
        assertEquals(-32022, ErrorCodes.UNSUPPORTED_FORMAT)
        assertEquals(-32023, ErrorCodes.ATTESTATION_FAILED)
        assertEquals(-32024, ErrorCodes.DEVICE_ATTESTATION_REQUIRED)
        assertEquals(-32025, ErrorCodes.PAIRING_REQUIRED)
    }

    @Test
    fun `every error code is unique`() {
        val collisions = errorCodesByName
            .groupBy { it.second }
            .filterValues { it.size > 1 }
            .map { (code, names) -> "$code shared by ${names.map { it.first }}" }

        assertTrue(
            "error codes must be distinct, or a peer cannot tell the " +
                "conditions apart on the wire: $collisions",
            collisions.isEmpty()
        )
    }

    @Test
    fun `every xKey specific error code sits in the JSON-RPC implementation-defined range`() {
        val jsonRpcStandard = setOf(
            ErrorCodes.PARSE_ERROR, ErrorCodes.INVALID_REQUEST, ErrorCodes.METHOD_NOT_FOUND,
            ErrorCodes.INVALID_PARAMS, ErrorCodes.INTERNAL_ERROR
        )

        allErrorCodes.filterNot { it in jsonRpcStandard }.forEach { code ->
            assertTrue(
                "error code $code must be inside the -32099..-32000 server-error range",
                code in -32099..-32000
            )
        }
    }

    @Test
    fun `no xKey specific error code collides with the reserved JSON-RPC codes`() {
        val reserved = setOf(-32700, -32600, -32601, -32602, -32603)
        val xkeySpecific = listOf(
            ErrorCodes.KEY_NOT_FOUND, ErrorCodes.USER_CANCELLED, ErrorCodes.BIOMETRIC_FAILED,
            ErrorCodes.BIOMETRIC_NOT_ENROLLED, ErrorCodes.BIOMETRIC_LOCKOUT,
            ErrorCodes.KEY_GENERATION_FAILED, ErrorCodes.SIGNING_FAILED, ErrorCodes.ENCRYPTION_FAILED,
            ErrorCodes.DECRYPTION_FAILED, ErrorCodes.INVALID_ALGORITHM, ErrorCodes.STRONGBOX_UNAVAILABLE,
            ErrorCodes.SESSION_EXPIRED, ErrorCodes.RATE_LIMITED, ErrorCodes.HMAC_FAILED,
            ErrorCodes.ECDH_FAILED, ErrorCodes.EXPORT_FAILED, ErrorCodes.ATTESTATION_FAILED,
            ErrorCodes.BACKEND_DENIED, ErrorCodes.OPERATION_DENIED, ErrorCodes.STORAGE_FULL,
            ErrorCodes.KEY_EXISTS, ErrorCodes.UNSUPPORTED_FORMAT, ErrorCodes.PAIRING_REJECTED,
            ErrorCodes.DEVICE_ATTESTATION_REQUIRED, ErrorCodes.PAIRING_REQUIRED,
            ErrorCodes.PIV_SLOT_NOT_FOUND, ErrorCodes.PIV_SLOT_OCCUPIED, ErrorCodes.PIV_SIGN_FAILED,
            ErrorCodes.PIV_INVALID_SLOT, ErrorCodes.PIN_REQUIRED, ErrorCodes.PIN_INCORRECT,
            ErrorCodes.PIN_LOCKED
        )

        xkeySpecific.forEach { code ->
            assertTrue("error code $code collides with a reserved JSON-RPC code", code !in reserved)
        }
    }
}
