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

import com.automatethethings.xkey.storage.entity.KeyEntity
import java.util.Base64

/**
 * The one place a FIDO2 byte field crosses the JSON-RPC wire.
 *
 * The desktop reads `credentialId`, `userId` and `userHandle` as Go `[]byte`
 * fields, which `encoding/json` decodes only from standard-alphabet, padded
 * base64. The phone stores the same ids as strings (URL-safe base64 for
 * every passkey it makes). [encode] turns a stored id into the wire form and
 * [resolve] turns a wire `credentialId` back into the stored passkey; no
 * handler sends or looks up a stored id string itself.
 *
 * A stored id maps to bytes by [wireId], the rule the CTAP2 BLE path uses,
 * so a passkey has one credential ID on every transport.
 */
internal object Fido2WireIds {

    /** Padded base64 comes in whole groups of four characters. */
    private const val BASE64_QUANTUM = 4

    /** Standard padded base64 of the bytes [stored] names. */
    fun encode(stored: String): String = Base64.getEncoder().encodeToString(wireId(stored))

    /**
     * The single FIDO2 passkey for [rpId] among [candidates] whose bytes are
     * [wire], or null when none is.
     *
     * @throws ProtocolException INVALID_PARAMS when [wire] is not standard
     *   padded base64; KEY_NOT_FOUND when two passkeys share those bytes, since
     *   neither can be named (the BLE path offers neither).
     */
    fun resolve(wire: String, rpId: String, candidates: List<KeyEntity>): KeyEntity? {
        // java.util.Base64's decoder accepts missing padding; Go's StdEncoding
        // does not, so neither does this.
        val bytes = try {
            require(wire.length % BASE64_QUANTUM == 0) { "unpadded" }
            Base64.getDecoder().decode(wire)
        } catch (e: IllegalArgumentException) {
            throw ProtocolException(
                "credentialId is not standard padded base64",
                errorCode = ErrorCodes.INVALID_PARAMS,
                cause = e
            )
        }
        if (bytes.isEmpty()) {
            throw ProtocolException("credentialId is empty", errorCode = ErrorCodes.INVALID_PARAMS)
        }
        val matches = candidates.filter {
            it.keyType == KeyTypes.FIDO2 && it.rpId == rpId && wireId(it.keyId).contentEquals(bytes)
        }
        if (matches.size > 1) {
            throw ProtocolException(
                "Credential ID names more than one passkey for $rpId",
                errorCode = ErrorCodes.KEY_NOT_FOUND
            )
        }
        return matches.singleOrNull()
    }

    /**
     * The credential ID a client sees for a stored key ID: its bytes
     * when the stored ID is base64 (URL-safe or standard, padded or not),
     * else the stored ID's own UTF-8 bytes. Never null, so every stored
     * passkey can be offered.
     */
    fun wireId(keyId: String): ByteArray = decodeBase64(keyId) ?: keyId.toByteArray(Charsets.UTF_8)

    /** Base64 in either alphabet, padded or not; null for anything else. */
    fun decodeBase64(text: String): ByteArray? {
        val bare = text.trimEnd('=')
        if (bare.isEmpty() || text.length - bare.length > 2) return null
        val decoder = when {
            bare.all { it.isLetterOrDigitAscii() || it == '-' || it == '_' } -> Base64.getUrlDecoder()
            bare.all { it.isLetterOrDigitAscii() || it == '+' || it == '/' } -> Base64.getDecoder()
            else -> return null
        }
        return try {
            decoder.decode(bare)
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private fun Char.isLetterOrDigitAscii(): Boolean = this in 'A'..'Z' || this in 'a'..'z' || this in '0'..'9'
}
