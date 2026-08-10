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
package com.automatethethings.xkey.audit

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [AuditLogEntity] construction and [AuditOperationType] enum
 * completeness.
 *
 * Verifies default values, nullable field handling, details JSON parsing,
 * and that all expected operation types are present in the enum.
 */
class AuditLoggerTest {

    // -----------------------------------------------------------------------
    // Entity construction tests
    // -----------------------------------------------------------------------

    @Test
    fun `KEY_CREATED entity has expected default values`() {
        val entity = AuditLogEntity(operationType = AuditOperationType.KEY_CREATED)

        assertEquals(0L, entity.id)
        assertEquals(AuditOperationType.KEY_CREATED, entity.operationType)
        assertTrue(entity.success)
        assertNull(entity.keyId)
        assertNull(entity.keyLabel)
        assertNull(entity.keyType)
        assertNull(entity.deviceId)
        assertNull(entity.deviceName)
        assertNull(entity.errorMessage)
        assertNull(entity.details)
        assertNull(entity.durationMs)
    }

    @Test
    fun `KEY_DELETED entity with keyId and keyLabel`() {
        val entity = AuditLogEntity(
            operationType = AuditOperationType.KEY_DELETED,
            keyId = "key-abc-123",
            keyLabel = "My Signing Key"
        )

        assertEquals(AuditOperationType.KEY_DELETED, entity.operationType)
        assertEquals("key-abc-123", entity.keyId)
        assertEquals("My Signing Key", entity.keyLabel)
        assertTrue(entity.success)
        assertNull(entity.errorMessage)
    }

    @Test
    fun `FIDO2_REGISTRATION with keyId keyLabel and details containing rpId`() {
        val details = JSONObject().apply {
            put("rpId", "webauthn.io")
            put("algorithm", "ES256")
        }.toString()

        val entity = AuditLogEntity(
            operationType = AuditOperationType.FIDO2_REGISTRATION,
            keyId = "fido2-cred-001",
            keyLabel = "webauthn.io",
            keyType = "fido2",
            details = details
        )

        assertEquals(AuditOperationType.FIDO2_REGISTRATION, entity.operationType)
        assertEquals("fido2-cred-001", entity.keyId)
        assertEquals("webauthn.io", entity.keyLabel)
        assertEquals("fido2", entity.keyType)

        val parsed = JSONObject(entity.details!!)
        assertEquals("webauthn.io", parsed.getString("rpId"))
        assertEquals("ES256", parsed.getString("algorithm"))
    }

    @Test
    fun `FIDO2_AUTHENTICATION with rpId in details`() {
        val details = JSONObject().apply {
            put("rpId", "example.com")
            put("userVerification", "required")
        }.toString()

        val entity = AuditLogEntity(
            operationType = AuditOperationType.FIDO2_AUTHENTICATION,
            keyId = "fido2-cred-002",
            keyType = "fido2",
            details = details
        )

        assertEquals(AuditOperationType.FIDO2_AUTHENTICATION, entity.operationType)

        val parsed = JSONObject(entity.details!!)
        assertEquals("example.com", parsed.getString("rpId"))
        assertEquals("required", parsed.getString("userVerification"))
    }

    @Test
    fun `SERVICE_STARTED with default values`() {
        val entity = AuditLogEntity(operationType = AuditOperationType.SERVICE_STARTED)

        assertEquals(AuditOperationType.SERVICE_STARTED, entity.operationType)
        assertTrue(entity.success)
        assertNull(entity.keyId)
        assertNull(entity.deviceId)
        assertNull(entity.details)
        assertTrue(entity.timestamp > 0)
    }

    @Test
    fun `SERVICE_STOPPED with default values`() {
        val entity = AuditLogEntity(operationType = AuditOperationType.SERVICE_STOPPED)

        assertEquals(AuditOperationType.SERVICE_STOPPED, entity.operationType)
        assertTrue(entity.success)
        assertNull(entity.keyId)
        assertNull(entity.deviceId)
        assertNull(entity.details)
        assertTrue(entity.timestamp > 0)
    }

    @Test
    fun `SETTINGS_CHANGED with details JSON containing setting name and value`() {
        val details = JSONObject().apply {
            put("setting", "ble_advertising_enabled")
            put("value", true)
        }.toString()

        val entity = AuditLogEntity(
            operationType = AuditOperationType.SETTINGS_CHANGED,
            details = details
        )

        assertEquals(AuditOperationType.SETTINGS_CHANGED, entity.operationType)
        assertTrue(entity.success)

        val parsed = JSONObject(entity.details!!)
        assertEquals("ble_advertising_enabled", parsed.getString("setting"))
        assertTrue(parsed.getBoolean("value"))
    }

    @Test
    fun `OATH_CREDENTIAL_CREATED with keyId and keyLabel`() {
        val entity = AuditLogEntity(
            operationType = AuditOperationType.OATH_CREDENTIAL_CREATED,
            keyId = "oath-github-totp",
            keyLabel = "GitHub (user@example.com)"
        )

        assertEquals(AuditOperationType.OATH_CREDENTIAL_CREATED, entity.operationType)
        assertEquals("oath-github-totp", entity.keyId)
        assertEquals("GitHub (user@example.com)", entity.keyLabel)
        assertTrue(entity.success)
    }

    // -----------------------------------------------------------------------
    // Enum completeness tests
    // -----------------------------------------------------------------------

    @Test
    fun `operation type count equals expected`() {
        val values = AuditOperationType.values()
        assertEquals(
            "AuditOperationType should have exactly 58 values",
            58,
            values.size
        )
    }

    @Test
    fun `key lifecycle types exist`() {
        val lifecycleTypes = listOf(
            AuditOperationType.KEY_CREATED,
            AuditOperationType.KEY_DELETED,
            AuditOperationType.KEY_USED,
            AuditOperationType.KEY_ATTESTED
        )

        lifecycleTypes.forEach { type ->
            assertNotNull(
                "${type.name} should be a valid AuditOperationType",
                AuditOperationType.valueOf(type.name)
            )
        }
    }

    @Test
    fun `FIDO2 types exist`() {
        val fido2Types = listOf(
            AuditOperationType.FIDO2_REGISTRATION,
            AuditOperationType.FIDO2_AUTHENTICATION
        )

        fido2Types.forEach { type ->
            assertNotNull(
                "${type.name} should be a valid AuditOperationType",
                AuditOperationType.valueOf(type.name)
            )
        }
    }

    // -----------------------------------------------------------------------
    // Details JSON validation
    // -----------------------------------------------------------------------

    @Test
    fun `details field parsed as valid JSON when set`() {
        val details = JSONObject().apply {
            put("algorithm", "ECDSA")
            put("curve", "P-256")
            put("purpose", "signing")
        }.toString()

        val entity = AuditLogEntity(
            operationType = AuditOperationType.KEY_CREATED,
            keyId = "key-json-test",
            details = details
        )

        assertNotNull(entity.details)

        val parsed = JSONObject(entity.details!!)
        assertEquals("ECDSA", parsed.getString("algorithm"))
        assertEquals("P-256", parsed.getString("curve"))
        assertEquals("signing", parsed.getString("purpose"))
        assertEquals(3, parsed.length())
    }
}
