package com.automatethethings.xkey.protocol

import java.lang.reflect.Modifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pins every ErrorCodes number to the go-xkms pkg/pairingproto/protocol.go registry. */
class ErrorCodeParityTest {

    private fun allCodes(): Map<String, Int> =
        ErrorCodes::class.java.declaredFields
            .filter { Modifier.isStatic(it.modifiers) && it.type == Int::class.javaPrimitiveType }
            .associate { it.name to it.getInt(null) }

    @Test
    fun jsonRpcStandardCodes() {
        assertEquals("ErrorCodeParseError", -32700, ErrorCodes.PARSE_ERROR)
        assertEquals("ErrorCodeInvalidRequest", -32600, ErrorCodes.INVALID_REQUEST)
        assertEquals("ErrorCodeMethodNotFound", -32601, ErrorCodes.METHOD_NOT_FOUND)
        assertEquals("ErrorCodeInvalidParams", -32602, ErrorCodes.INVALID_PARAMS)
        assertEquals("ErrorCodeInternalError", -32603, ErrorCodes.INTERNAL_ERROR)
    }

    @Test
    fun codesSharedWithDesktop() {
        assertEquals("ErrorCodeKeyNotFound", -32000, ErrorCodes.KEY_NOT_FOUND)
        assertEquals("ErrorCodeUserCancelled", -32001, ErrorCodes.USER_CANCELLED)
        assertEquals("ErrorCodeBiometricFailed", -32002, ErrorCodes.BIOMETRIC_FAILED)
        assertEquals("ErrorCodeKeyExists", -32003, ErrorCodes.KEY_EXISTS)
        assertEquals("ErrorCodeUnsupportedAlg", -32004, ErrorCodes.INVALID_ALGORITHM)
        assertEquals("ErrorCodeStorageFull", -32006, ErrorCodes.STORAGE_FULL)
        assertEquals("ErrorCodeBackendDenied", -32008, ErrorCodes.BACKEND_DENIED)
        assertEquals("ErrorCodeAttestFailed", -32009, ErrorCodes.ATTESTATION_FAILED)
        assertEquals("ErrorCodeOperationDenied", -32011, ErrorCodes.OPERATION_DENIED)
        assertEquals("ErrorCodeDecryptFailed", -32013, ErrorCodes.DECRYPTION_FAILED)
        assertEquals("ErrorCodeHMACFailed", -32014, ErrorCodes.HMAC_FAILED)
        assertEquals("ErrorCodeECDHFailed", -32015, ErrorCodes.ECDH_FAILED)
        assertEquals("ErrorCodeInvalidFormat", -32016, ErrorCodes.UNSUPPORTED_FORMAT)
        assertEquals("ErrorCodePairingRejected", -32017, ErrorCodes.PAIRING_REJECTED)
        assertEquals("ErrorCodePIVSlotNotFound", -32026, ErrorCodes.PIV_SLOT_NOT_FOUND)
        assertEquals("ErrorCodePIVSlotOccupied", -32027, ErrorCodes.PIV_SLOT_OCCUPIED)
        assertEquals("ErrorCodePIVSignFailed", -32028, ErrorCodes.PIV_SIGN_FAILED)
        assertEquals("ErrorCodePIVInvalidSlot", -32029, ErrorCodes.PIV_INVALID_SLOT)
        assertEquals("ErrorCodeFeatureUnavailable", -32035, ErrorCodes.FEATURE_UNAVAILABLE)
        assertEquals("ErrorCodeNotApplicable", -32036, ErrorCodes.NOT_APPLICABLE)
        assertEquals("ErrorCodeAttestProtocolDowngrade", -32037, ErrorCodes.ATTEST_PROTOCOL_DOWNGRADE)
    }

    @Test
    fun phoneOnlyCodesSitAboveDesktopBlock() {
        assertEquals("phone-only", -32041, ErrorCodes.BIOMETRIC_NOT_ENROLLED)
        assertEquals("phone-only", -32042, ErrorCodes.BIOMETRIC_LOCKOUT)
        assertEquals("phone-only", -32043, ErrorCodes.KEY_GENERATION_FAILED)
        assertEquals("phone-only", -32044, ErrorCodes.SIGNING_FAILED)
        assertEquals("phone-only", -32045, ErrorCodes.ENCRYPTION_FAILED)
        assertEquals("phone-only", -32046, ErrorCodes.STRONGBOX_UNAVAILABLE)
        assertEquals("phone-only", -32047, ErrorCodes.SESSION_EXPIRED)
        assertEquals("phone-only", -32048, ErrorCodes.RATE_LIMITED)
        assertEquals("phone-only", -32049, ErrorCodes.EXPORT_FAILED)
        assertEquals("phone-only", -32050, ErrorCodes.DEVICE_ATTESTATION_REQUIRED)
        assertEquals("phone-only", -32051, ErrorCodes.PAIRING_REQUIRED)
        assertEquals("phone-only", -32052, ErrorCodes.PIN_REQUIRED)
        assertEquals("phone-only", -32053, ErrorCodes.PIN_INCORRECT)
        assertEquals("phone-only", -32054, ErrorCodes.PIN_LOCKED)
        assertEquals("phone-only", -32055, ErrorCodes.VAULT_NOT_INITIALIZED)
        assertEquals("phone-only", -32056, ErrorCodes.VAULT_CREDENTIAL_REJECTED)
        assertEquals("phone-only", -32057, ErrorCodes.PASSWORD_STORE_LOCKED)
    }

    @Test
    fun allCodesPinned() {
        assertEquals(43, allCodes().size)
    }

    @Test
    fun allCodesDistinct() {
        val byValue = allCodes().entries.groupBy({ it.value }, { it.key })
        val dupes = byValue.filterValues { it.size > 1 }
        assertTrue("duplicate codes: $dupes", dupes.isEmpty())
    }

    @Test
    fun applicationCodesInServerErrorRange() {
        val standard = setOf(-32700, -32600, -32601, -32602, -32603)
        allCodes().filterValues { it !in standard }.forEach { (name, code) ->
            assertTrue("$name = $code outside -32099..-32000", code in -32099..-32000)
        }
    }
}
