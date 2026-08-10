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
package com.automatethethings.xkey.ca

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The JSON a refused enrollment is persisted as.
 *
 * `EnrolledDeviceRepository` stores the refusal list as the string produced
 * here, and `DeviceDetailActivity` is the only thing that reads it back. A
 * field that fails to serialise is a device whose screen says nothing about why
 * it has no certificate, which is the state this feature exists to end.
 *
 * `org.json` is the real implementation on the unit-test classpath; no
 * `android.util.Base64` is involved, because a refusal is text and a timestamp.
 * The repository itself needs EncryptedSharedPreferences and is covered by the
 * instrumented `EnrolledDeviceRefusalStoreTest`.
 */
class EnrollmentRefusalRecordJsonTest {

    private val record = EnrollmentRefusalRecord(
        deviceId = "aabbccdd",
        deviceName = "Workshop Laptop",
        refusal = EnrollmentRefusal.ActivationMismatch(
            "credential activation returned a different secret"
        ),
        refusedAt = 1_770_000_000_000L
    )

    @Test
    fun `a record round trips`() {
        val restored = EnrollmentRefusalRecord.fromJson(record.toJson())

        assertEquals(record, restored)
    }

    @Test
    fun `every case round trips`() {
        listOf(
            EnrollmentRefusal.MalformedPackage("does not parse"),
            EnrollmentRefusal.UntrustedEndorsement("self-signed"),
            EnrollmentRefusal.ActivationMismatch("different secret"),
            EnrollmentRefusal.ActivationUnsupported("no RSA endorsement key"),
            EnrollmentRefusal.QuoteInvalid("nonce this CA did not send")
        ).forEach { refusal ->
            val restored = EnrollmentRefusalRecord.fromJson(record.copy(refusal = refusal).toJson())
            assertEquals(refusal, restored?.refusal)
        }
    }

    @Test
    fun `the case and the detail are stored as separate fields`() {
        val json = record.toJson()

        // The case has to be readable without parsing the message, which is the
        // whole point of typing the refusal.
        assertEquals("activation-mismatch", json.getString("case"))
        assertEquals("credential activation returned a different secret", json.getString("detail"))
    }

    @Test
    fun `the device and the time it was refused survive`() {
        val json = record.toJson()

        assertEquals("aabbccdd", json.getString("deviceId"))
        assertEquals("Workshop Laptop", json.getString("deviceName"))
        assertEquals(1_770_000_000_000L, json.getLong("refusedAt"))
    }

    @Test
    fun `a case this build does not know reads back as nothing`() {
        val json = record.toJson().apply { put("case", "invented-by-a-newer-build") }

        assertNull(EnrollmentRefusalRecord.fromJson(json))
    }

    @Test
    fun `a record with no detail still loads`() {
        val json = JSONObject().apply {
            put("deviceId", "aabbccdd")
            put("deviceName", "Workshop Laptop")
            put("case", "quote-invalid")
            put("refusedAt", 1L)
        }

        val restored = EnrollmentRefusalRecord.fromJson(json)

        assertNotNull(restored)
        assertEquals(EnrollmentRefusal.QuoteInvalid(""), restored?.refusal)
    }

    @Test
    fun `a long detail is not truncated`() {
        val detail = "EK certificate does not chain to a trusted TPM vendor root: " +
            "unable to find valid certification path to requested target"
        val restored = EnrollmentRefusalRecord.fromJson(
            record.copy(refusal = EnrollmentRefusal.UntrustedEndorsement(detail)).toJson()
        )

        assertEquals(detail, restored?.refusal?.detail)
    }
}
