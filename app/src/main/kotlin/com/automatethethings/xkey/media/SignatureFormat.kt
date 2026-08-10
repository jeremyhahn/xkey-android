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

import org.json.JSONArray
import org.json.JSONObject

enum class SignerRole { CREATOR, WITNESS, ATTESTOR }

data class SignatureEntry(
    val keyFingerprint: String,
    val signerName: String?,
    val algorithm: String,
    val value: String,
    val timestamp: String,
    val role: SignerRole = SignerRole.CREATOR
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("keyFingerprint", keyFingerprint)
        signerName?.let { put("signerName", it) }
        put("algorithm", algorithm)
        put("value", value)
        put("timestamp", timestamp)
        put("role", role.name)
    }

    companion object {
        fun fromJson(json: JSONObject): SignatureEntry = SignatureEntry(
            keyFingerprint = json.getString("keyFingerprint"),
            signerName = if (json.has("signerName") && !json.isNull("signerName")) json.getString("signerName") else null,
            algorithm = json.getString("algorithm"),
            value = json.getString("value"),
            timestamp = json.getString("timestamp"),
            role = try { SignerRole.valueOf(json.optString("role", "CREATOR")) } catch (_: Exception) { SignerRole.CREATOR }
        )
    }
}

data class ContentAuthenticityData(
    val version: Int = 1,
    val contentHash: String,
    val hashAlgorithm: String = "SHA-256",
    val signatures: List<SignatureEntry>
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("version", version)
        put("contentHash", contentHash)
        put("hashAlgorithm", hashAlgorithm)
        put("signatures", JSONArray().apply {
            signatures.forEach { put(it.toJson()) }
        })
    }

    fun toJsonString(): String = toJson().toString()

    companion object {
        fun fromJson(json: JSONObject): ContentAuthenticityData {
            val sigArray = json.getJSONArray("signatures")
            val signatures = (0 until sigArray.length()).map {
                SignatureEntry.fromJson(sigArray.getJSONObject(it))
            }
            return ContentAuthenticityData(
                version = json.optInt("version", 1),
                contentHash = json.getString("contentHash"),
                hashAlgorithm = json.optString("hashAlgorithm", "SHA-256"),
                signatures = signatures
            )
        }

        fun fromJsonString(jsonString: String): ContentAuthenticityData =
            fromJson(JSONObject(jsonString))
    }
}
