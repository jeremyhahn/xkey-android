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
package com.automatethethings.xkey.media

import org.json.JSONException
import org.json.JSONObject
import java.time.Clock
import java.time.Instant
import java.util.Base64

/**
 * The owner's co-sign request QR: `{"v":1,"hash","alg","from"}`.
 *
 * [contentHash] is the lowercase hex digest of the media under [hashAlgorithm];
 * [ownerFingerprint] is the owner's key fingerprint, shown to the witness
 * before they approve.
 */
data class CoSignRequest(
    val contentHash: String,
    val hashAlgorithm: String,
    val ownerFingerprint: String
) {
    fun toJsonString(): String = JSONObject().apply {
        put("v", CoSignPayload.VERSION)
        put("hash", contentHash)
        put("alg", hashAlgorithm)
        put("from", ownerFingerprint)
    }.toString()

    /** The digest bytes the witness signs. Valid for a parsed request. */
    fun hashBytes(): ByteArray =
        contentHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    companion object {
        fun of(data: ContentAuthenticityData, ownerFingerprint: String): CoSignRequest =
            CoSignRequest(data.contentHash, data.hashAlgorithm, ownerFingerprint)
    }
}

/**
 * The witness's co-sign response QR: `{"v":1,"sig","fp","name","alg"}`.
 *
 * [signature] is the base64 signature over the request's digest bytes.
 */
data class CoSignResponse(
    val signature: String,
    val fingerprint: String,
    val signerName: String,
    val algorithm: String
) {
    fun toJsonString(): String = JSONObject().apply {
        put("v", CoSignPayload.VERSION)
        put("sig", signature)
        put("fp", fingerprint)
        put("name", signerName)
        put("alg", algorithm)
    }.toString()

    /** The co-signature as an ATTESTOR entry, timestamped (ISO-8601) by [clock]. */
    fun toAttestorEntry(clock: Clock): SignatureEntry = SignatureEntry(
        keyFingerprint = fingerprint,
        signerName = signerName,
        algorithm = algorithm,
        value = signature,
        timestamp = Instant.now(clock).toString(),
        role = SignerRole.ATTESTOR
    )
}

/** Why a scanned co-sign payload was refused. */
sealed class CoSignPayloadError {
    /** The payload is not a JSON object. */
    data object NotJson : CoSignPayloadError()

    /** The `v` field is not a supported version; null when it is not a number. */
    data class UnsupportedVersion(val version: Int?) : CoSignPayloadError()

    /** A required field is absent, null or blank. */
    data class MissingField(val field: String) : CoSignPayloadError()

    /** The request's hash algorithm is not one xKey hashes media with. */
    data class UnsupportedHashAlgorithm(val algorithm: String) : CoSignPayloadError()

    /** The request's hash is not lowercase hex of the algorithm's digest length. */
    data object InvalidHash : CoSignPayloadError()

    /** The response's signature is not base64. */
    data object InvalidSignature : CoSignPayloadError()
}

sealed class CoSignParseResult<out T> {
    data class Ok<T>(val value: T) : CoSignParseResult<T>()
    data class Failed(val error: CoSignPayloadError) : CoSignParseResult<Nothing>()
}

sealed class CoSignAppendResult {
    data class Appended(val data: ContentAuthenticityData) : CoSignAppendResult()

    /** [fingerprint] has already signed this media; nothing was appended. */
    data class DuplicateSigner(val fingerprint: String) : CoSignAppendResult()
}

/** Parses the co-sign QR payloads and appends a witness co-signature. Pure: no Android APIs. */
object CoSignPayload {
    const val VERSION = 1

    private val DIGEST_HEX_LENGTH = mapOf(
        "SHA-256" to 64,
        "SHA-384" to 96,
        "SHA-512" to 128
    )

    private val LOWER_HEX = Regex("^[0-9a-f]+$")

    fun parseRequest(raw: String): CoSignParseResult<CoSignRequest> {
        val json = parseObject(raw) ?: return failed(CoSignPayloadError.NotJson)
        checkVersion(json)?.let { return failed(it) }
        val hash = field(json, "hash") ?: return missing("hash")
        val alg = field(json, "alg") ?: return missing("alg")
        val from = field(json, "from") ?: return missing("from")
        val length = DIGEST_HEX_LENGTH[alg]
            ?: return failed(CoSignPayloadError.UnsupportedHashAlgorithm(alg))
        if (hash.length != length || !LOWER_HEX.matches(hash)) {
            return failed(CoSignPayloadError.InvalidHash)
        }
        return CoSignParseResult.Ok(CoSignRequest(hash, alg, from))
    }

    fun parseResponse(raw: String): CoSignParseResult<CoSignResponse> {
        val json = parseObject(raw) ?: return failed(CoSignPayloadError.NotJson)
        checkVersion(json)?.let { return failed(it) }
        val sig = field(json, "sig") ?: return missing("sig")
        val fp = field(json, "fp") ?: return missing("fp")
        val name = field(json, "name") ?: return missing("name")
        val alg = field(json, "alg") ?: return missing("alg")
        if (!isBase64(sig)) return failed(CoSignPayloadError.InvalidSignature)
        return CoSignParseResult.Ok(CoSignResponse(sig, fp, name, alg))
    }

    /**
     * Appends [entry] to [data], or refuses it when its key fingerprint has
     * already signed. [data] itself is never modified.
     */
    fun appendAttestor(data: ContentAuthenticityData, entry: SignatureEntry): CoSignAppendResult {
        val duplicate = data.signatures.any { it.keyFingerprint.equals(entry.keyFingerprint, ignoreCase = true) }
        if (duplicate) return CoSignAppendResult.DuplicateSigner(entry.keyFingerprint)
        return CoSignAppendResult.Appended(data.copy(signatures = data.signatures + entry))
    }

    private fun parseObject(raw: String): JSONObject? {
        val trimmed = raw.trim()
        if (!trimmed.startsWith("{")) return null
        return try {
            JSONObject(trimmed)
        } catch (_: JSONException) {
            null
        }
    }

    private fun checkVersion(json: JSONObject): CoSignPayloadError? {
        if (!json.has("v") || json.isNull("v")) return CoSignPayloadError.MissingField("v")
        val v = json.get("v")
        val version = (v as? Number)?.takeIf { it.toDouble() == it.toInt().toDouble() }?.toInt()
        return if (version == VERSION) null else CoSignPayloadError.UnsupportedVersion(version)
    }

    private fun field(json: JSONObject, name: String): String? {
        if (!json.has(name) || json.isNull(name)) return null
        return json.optString(name).takeIf { it.isNotBlank() }
    }

    private fun isBase64(value: String): Boolean = try {
        Base64.getDecoder().decode(value).isNotEmpty()
    } catch (_: IllegalArgumentException) {
        false
    }

    private fun failed(error: CoSignPayloadError): CoSignParseResult.Failed = CoSignParseResult.Failed(error)

    private fun missing(field: String): CoSignParseResult.Failed = failed(CoSignPayloadError.MissingField(field))
}
