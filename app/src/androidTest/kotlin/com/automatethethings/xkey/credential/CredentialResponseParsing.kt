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

package com.automatethethings.xkey.credential

/**
 * Readers for the two binary structures a relying party actually parses:
 * authenticator data and the CBOR attestation object.
 *
 * These decode from the wire rather than re-implementing the producer, so a
 * test asserting on them fails if the handler's encoding drifts.
 */

/**
 * Authenticator data (W3C WebAuthn Level 3, section 6.1).
 *
 * Layout: `rpIdHash(32) || flags(1) || signCount(4)` and, when the `AT` flag is
 * set, `aaguid(16) || credentialIdLength(2) || credentialId || COSE key`.
 */
class AuthenticatorData(val raw: ByteArray) {

    init {
        require(raw.size >= 37) { "authenticator data is ${raw.size} bytes, minimum is 37" }
    }

    /** SHA-256 of the relying party identifier. */
    val rpIdHash: ByteArray get() = raw.copyOfRange(0, 32)

    /** The flag byte, as an unsigned value. */
    val flags: Int get() = raw[32].toInt() and 0xFF

    /** Bit 0 — a user was present. */
    val userPresent: Boolean get() = flags and 0x01 != 0

    /** Bit 2 — a user was verified. */
    val userVerified: Boolean get() = flags and 0x04 != 0

    /** Bit 6 — attested credential data follows. */
    val attestedCredentialData: Boolean get() = flags and 0x40 != 0

    /** Big-endian 32-bit signature counter. */
    val signCount: Long
        get() = ((raw[33].toLong() and 0xFF) shl 24) or
            ((raw[34].toLong() and 0xFF) shl 16) or
            ((raw[35].toLong() and 0xFF) shl 8) or
            (raw[36].toLong() and 0xFF)

    /** Authenticator model identifier; all zeros for "none" attestation. */
    val aaguid: ByteArray
        get() {
            requireAttested()
            return raw.copyOfRange(37, 53)
        }

    /** The big-endian length prefix that precedes the credential id. */
    val credentialIdLength: Int
        get() {
            requireAttested()
            return ((raw[53].toInt() and 0xFF) shl 8) or (raw[54].toInt() and 0xFF)
        }

    /** The credential id, sized by [credentialIdLength]. */
    val credentialId: ByteArray
        get() {
            val length = credentialIdLength
            require(55 + length <= raw.size) {
                "credential id length $length overruns ${raw.size}-byte authenticator data"
            }
            return raw.copyOfRange(55, 55 + length)
        }

    /** Everything after the credential id: the COSE_Key public key. */
    val coseKey: ByteArray
        get() = raw.copyOfRange(55 + credentialIdLength, raw.size)

    private fun requireAttested() {
        require(attestedCredentialData) {
            "authenticator data has no attested credential data (flags=0x${flags.toString(16)})"
        }
    }
}

/** The decoded `attestationObject` of a registration response. */
data class AttestationObject(
    val fmt: String,
    val attestationStatementEntryCount: Int,
    val authData: ByteArray
)

/**
 * A deliberately strict CBOR reader.
 *
 * It accepts only the subset the attestation object uses and rejects trailing
 * bytes, so a malformed encoding surfaces as a failure instead of being
 * silently tolerated the way a lenient parser would.
 */
class CborReader(private val bytes: ByteArray) {

    var position: Int = 0
        private set

    /** @return the number of key/value pairs in the map that starts here. */
    fun readMapHeader(): Int {
        val (major, value) = readHead()
        require(major == 5) { "expected a CBOR map at $position, got major type $major" }
        return value.toInt()
    }

    /** @return the UTF-8 text string that starts here. */
    fun readTextString(): String {
        val (major, value) = readHead()
        require(major == 3) { "expected a CBOR text string at $position, got major type $major" }
        val length = value.toInt()
        require(position + length <= bytes.size) { "CBOR text string overruns the buffer" }
        val text = String(bytes, position, length, Charsets.UTF_8)
        position += length
        return text
    }

    /** @return the byte string that starts here. */
    fun readByteString(): ByteArray {
        val (major, value) = readHead()
        require(major == 2) { "expected a CBOR byte string at $position, got major type $major" }
        val length = value.toInt()
        require(position + length <= bytes.size) { "CBOR byte string overruns the buffer" }
        val slice = bytes.copyOfRange(position, position + length)
        position += length
        return slice
    }

    /** Whether every byte has been consumed. */
    fun atEnd(): Boolean = position == bytes.size

    private fun readHead(): Pair<Int, Long> {
        require(position < bytes.size) { "CBOR data is truncated at $position" }
        val initial = bytes[position++].toInt() and 0xFF
        val major = initial shr 5
        val additional = initial and 0x1F
        val value: Long = when {
            additional < 24 -> additional.toLong()
            additional == 24 -> readUnsigned(1)
            additional == 25 -> readUnsigned(2)
            additional == 26 -> readUnsigned(4)
            else -> throw IllegalArgumentException("unsupported CBOR additional info $additional")
        }
        return major to value
    }

    private fun readUnsigned(byteCount: Int): Long {
        require(position + byteCount <= bytes.size) { "CBOR length field is truncated" }
        var value = 0L
        repeat(byteCount) {
            value = (value shl 8) or (bytes[position++].toLong() and 0xFF)
        }
        return value
    }
}

/**
 * Decodes `{"fmt": ..., "attStmt": {...}, "authData": h'...'}`.
 *
 * @throws IllegalArgumentException if the bytes are not exactly that map.
 */
fun parseAttestationObject(bytes: ByteArray): AttestationObject {
    val reader = CborReader(bytes)
    val entryCount = reader.readMapHeader()
    require(entryCount == 3) { "attestation object should have 3 entries, has $entryCount" }

    var fmt: String? = null
    var attestationStatementEntries: Int? = null
    var authData: ByteArray? = null

    repeat(entryCount) {
        when (val key = reader.readTextString()) {
            "fmt" -> fmt = reader.readTextString()
            "attStmt" -> attestationStatementEntries = reader.readMapHeader()
            "authData" -> authData = reader.readByteString()
            else -> throw IllegalArgumentException("unexpected attestation object key '$key'")
        }
    }
    require(reader.atEnd()) {
        "attestation object has ${bytes.size - reader.position} trailing bytes"
    }

    return AttestationObject(
        fmt = requireNotNull(fmt) { "attestation object has no 'fmt'" },
        attestationStatementEntryCount = requireNotNull(attestationStatementEntries) {
            "attestation object has no 'attStmt'"
        },
        authData = requireNotNull(authData) { "attestation object has no 'authData'" }
    )
}
