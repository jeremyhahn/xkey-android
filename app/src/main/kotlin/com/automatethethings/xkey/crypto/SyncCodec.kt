// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.crypto

import java.security.MessageDigest
import java.time.DateTimeException
import java.time.Instant
import java.util.Base64

/**
 * A value from a sync peer (a PEM body, a timestamp) that does not decode.
 * The message names the field's problem and never quotes the value.
 */
class MalformedSyncValueException(message: String) : IllegalArgumentException(message)

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

    /**
     * Decodes a PEM block body to DER bytes.
     *
     * @throws MalformedSyncValueException when the body is empty or not
     *   base64; the message never quotes the input.
     */
    fun pemToDer(pem: String): ByteArray {
        val b64 = pem.lineSequence()
            .filterNot { it.startsWith("-----") }
            .joinToString("")
            .replace("\\s".toRegex(), "")
        if (b64.isEmpty()) throw MalformedSyncValueException("PEM body is empty")
        return try {
            Base64.getDecoder().decode(b64)
        } catch (e: IllegalArgumentException) {
            // The decoder's message quotes a character of the input: not carried.
            throw MalformedSyncValueException("PEM body is not base64")
        }
    }

    /** Encodes DER certificate bytes as a PEM CERTIFICATE block. */
    fun derToPem(der: ByteArray): String {
        val body = Base64.getEncoder().encodeToString(der).chunked(64).joinToString("\n")
        return "-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----\n"
    }

    /** Formats epoch millis as RFC 3339, or "" for non-positive. */
    fun toRfc3339(millis: Long): String =
        if (millis <= 0) "" else Instant.ofEpochMilli(millis).toString()

    /**
     * Parses an RFC 3339 timestamp to epoch millis. A blank value means "no
     * timestamp" and is 0.
     *
     * @throws MalformedSyncValueException when a non-blank value is not an
     *   RFC 3339 timestamp with a zone; the message never quotes the input.
     */
    fun parseRfc3339(value: String): Long {
        if (value.isBlank()) return 0L
        return try {
            Instant.parse(value).toEpochMilli()
        } catch (e: DateTimeException) {
            throw MalformedSyncValueException("timestamp is not RFC 3339")
        } catch (e: ArithmeticException) {
            throw MalformedSyncValueException("timestamp is out of range")
        }
    }
}
