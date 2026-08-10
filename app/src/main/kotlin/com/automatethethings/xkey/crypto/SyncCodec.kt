// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.crypto

import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

/**
 * Stateless codec/format helpers shared by the sync engine, key-sharing, and
 * backup handlers: PEM<->DER conversion, SHA-256 hex digests, store checksums,
 * and RFC 3339 time formatting.
 *
 * Single source of truth so the inbound (local.*) handlers, the outbound
 * (remote.*) sync client, and the sharing/backup handlers share one
 * implementation rather than duplicating these conversions.
 */
object SyncCodec {
    /** Lowercase hex SHA-256 of [data]. */
    fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

    /** Order-independent SHA-256 hex checksum over a set of item keys. */
    fun storeChecksum(items: List<String>): String =
        sha256Hex(items.sorted().joinToString("\n").toByteArray(Charsets.UTF_8))

    /** Decodes a PEM block body to DER bytes, or null if malformed/empty. */
    fun pemToDer(pem: String): ByteArray? = try {
        val b64 = pem.lineSequence()
            .filterNot { it.startsWith("-----") }
            .joinToString("")
            .replace("\\s".toRegex(), "")
        if (b64.isEmpty()) null else Base64.getDecoder().decode(b64)
    } catch (e: Exception) {
        null
    }

    /** Encodes DER certificate bytes as a PEM CERTIFICATE block. */
    fun derToPem(der: ByteArray): String {
        val body = Base64.getEncoder().encodeToString(der).chunked(64).joinToString("\n")
        return "-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----\n"
    }

    /** Formats epoch millis as RFC 3339, or "" for non-positive. */
    fun toRfc3339(millis: Long): String =
        if (millis <= 0) "" else Instant.ofEpochMilli(millis).toString()

    /** Parses an RFC 3339 timestamp to epoch millis, or 0 on failure/blank. */
    fun parseRfc3339(value: String): Long =
        if (value.isBlank()) 0L else try {
            Instant.parse(value).toEpochMilli()
        } catch (e: Exception) {
            0L
        }
}
