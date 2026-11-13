// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.remote

import android.util.Log
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.Response
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicLong

/**
 * Phone-to-desktop OATH calls over the paired Noise channel:
 *
 * - `remote.oathAdd`: store a phone credential in the desktop's OATH store.
 * - `remote.oathGenerate`: ask the desktop for the current code of a
 *   credential it holds.
 *
 * Wire shapes follow go-xkms `pkg/pairing/protocol_oath.go`
 * (RemoteOATHAddParams / OATHCredentialInfo / RemoteOATHAddResult and
 * RemoteOATHGenerateParams / RemoteOATHGenerateResult). Replies are type
 * checked strictly; anything off-shape throws [ProtocolException].
 *
 * The oathAdd request body is assembled by hand so the Base32 secret never
 * lands in a String: the caller's [Credential.secret] and the encoded body are
 * zeroed once the request has been sent (or has failed).
 */
class RemoteOathClient(
    desktop: ConnectedDesktop,
    private val requestTimeoutMs: Long = 30_000L
) {
    /** Bound to [desktop]'s connection: a reply-awaiting call never reaches another desktop. */
    private val messageSender: MessageSender = desktop.sender
    private val messageRouter: BidirectionalMessageRouter = desktop.router

    /**
     * An OATHCredentialInfo to send. [secret] is Base32 (RFC 4648, upper
     * case) and is zeroed by [oathAdd]. [type] is "totp" or "hotp".
     */
    class Credential(
        val name: String,
        val issuer: String?,
        val accountName: String?,
        val secret: CharArray,
        val type: String,
        val algorithm: String = "SHA1",
        val digits: Int = 6,
        val period: Int = 30,
        val counter: Long = 0
    )

    /** RemoteOATHAddResult. */
    data class AddResult(val success: Boolean, val credentialId: String, val message: String?)

    /** RemoteOATHGenerateResult; [expiresIn] is seconds, null for HOTP. */
    data class GenerateResult(val code: String, val expiresIn: Int?)

    /**
     * Stores [credential] on the desktop and returns the desktop's
     * credential ID. The secret is zeroed whatever the outcome.
     */
    suspend fun oathAdd(credential: Credential): AddResult {
        try {
            validate(credential)
            val id = nextId.incrementAndGet()
            val body = encodeAdd(id, credential)
            val result = try {
                send(id, MethodNames.REMOTE_OATH_ADD, body)
            } finally {
                body.fill(0)
            }
            return parseAdd(result)
        } finally {
            credential.secret.fill('\u0000')
        }
    }

    /** Asks the desktop for the current code of [credentialId]. */
    suspend fun oathGenerate(credentialId: String): GenerateResult {
        if (credentialId.isBlank()) invalid("credential_id is empty")
        val id = nextId.incrementAndGet()
        val json = JSONObject()
            .put("id", id)
            .put("method", MethodNames.REMOTE_OATH_GENERATE)
            .put("params", JSONObject().put("credential_id", credentialId))
        return parseGenerate(send(id, MethodNames.REMOTE_OATH_GENERATE, json.toString().toByteArray(Charsets.UTF_8)))
    }

    private suspend fun send(id: Long, method: String, body: ByteArray): JSONObject {
        val deferred = CompletableDeferred<Response>()
        messageRouter.registerPendingResponse(id, deferred)
        try {
            messageSender.sendEncryptedMessage(body)
            val response = try {
                withTimeout(requestTimeoutMs) { deferred.await() }
            } catch (e: TimeoutCancellationException) {
                throw ProtocolException("Request timed out: $method", e, ErrorCodes.INTERNAL_ERROR)
            }
            val error = response.error
            if (error != null) {
                Log.w(TAG, "$method failed: ${error.code}")
                throw ProtocolException("Remote error: ${error.message}", errorCode = error.code)
            }
            return response.result ?: malformed("$method: missing result")
        } finally {
            messageRouter.removePendingResponse(id)
        }
    }

    private fun validate(c: Credential) {
        if (c.name.isEmpty()) invalid("name is empty")
        if (c.secret.isEmpty()) invalid("secret is empty")
        if (!c.secret.all { it in 'A'..'Z' || it in '2'..'7' || it == '=' }) invalid("secret is not Base32")
        if (c.type != TYPE_TOTP && c.type != TYPE_HOTP) invalid("type must be totp or hotp")
        if (c.algorithm !in ALGORITHMS) invalid("unsupported algorithm")
        if (c.digits !in 6..8) invalid("digits must be 6 to 8")
        if (c.type == TYPE_TOTP && c.period <= 0) invalid("period must be positive")
        if (c.counter < 0) invalid("counter is negative")
    }

    /** `{"id":N,"method":"remote.oathAdd","params":{"credential":{...,"secret":"…"}}}` */
    private fun encodeAdd(id: Long, c: Credential): ByteArray {
        val head = StringBuilder()
            .append("{\"id\":").append(id)
            .append(",\"method\":").append(JSONObject.quote(MethodNames.REMOTE_OATH_ADD))
            .append(",\"params\":{\"credential\":{")
            .append("\"name\":").append(JSONObject.quote(c.name))
        if (!c.issuer.isNullOrEmpty()) head.append(",\"issuer\":").append(JSONObject.quote(c.issuer))
        if (!c.accountName.isNullOrEmpty()) head.append(",\"account_name\":").append(JSONObject.quote(c.accountName))
        head.append(",\"type\":").append(JSONObject.quote(c.type))
        head.append(",\"algorithm\":").append(JSONObject.quote(c.algorithm))
        head.append(",\"digits\":").append(c.digits)
        if (c.type == TYPE_TOTP) head.append(",\"period\":").append(c.period)
        if (c.type == TYPE_HOTP && c.counter > 0) head.append(",\"counter\":").append(c.counter)
        head.append(",\"secret\":\"")
        val prefix = head.toString().toByteArray(Charsets.UTF_8)
        val suffix = "\"}}}".toByteArray(Charsets.UTF_8)
        val out = ByteArray(prefix.size + c.secret.size + suffix.size)
        prefix.copyInto(out)
        for (i in c.secret.indices) out[prefix.size + i] = c.secret[i].code.toByte()
        suffix.copyInto(out, prefix.size + c.secret.size)
        return out
    }

    private fun parseAdd(r: JSONObject): AddResult {
        val success = r.opt("success") as? Boolean ?: malformed("oathAdd: success is not a boolean")
        val message = optString(r, "message", "oathAdd")
        if (!success) {
            throw ProtocolException(
                "Desktop refused the credential: ${message ?: "no reason given"}",
                errorCode = ErrorCodes.INTERNAL_ERROR
            )
        }
        val credentialId = r.opt("credential_id") as? String ?: malformed("oathAdd: credential_id is not a string")
        if (credentialId.isEmpty()) malformed("oathAdd: credential_id is empty")
        return AddResult(success, credentialId, message)
    }

    private fun parseGenerate(r: JSONObject): GenerateResult {
        val code = r.opt("code") as? String ?: malformed("oathGenerate: code is not a string")
        if (code.isEmpty() || !code.all { it in '0'..'9' }) malformed("oathGenerate: code is not digits")
        val raw = r.opt("expires_in")
        val expiresIn = when {
            raw == null || raw == JSONObject.NULL -> null
            raw is Int -> raw
            raw is Long && raw in 0..Int.MAX_VALUE -> raw.toInt()
            else -> malformed("oathGenerate: expires_in is not an integer")
        }
        if (expiresIn != null && expiresIn < 0) malformed("oathGenerate: expires_in is negative")
        return GenerateResult(code, expiresIn)
    }

    private fun optString(r: JSONObject, key: String, method: String): String? {
        val v = r.opt(key)
        return when (v) {
            null, JSONObject.NULL -> null
            is String -> v
            else -> malformed("$method: $key is not a string")
        }
    }

    private fun invalid(why: String): Nothing =
        throw ProtocolException("Invalid OATH request: $why", errorCode = ErrorCodes.INVALID_PARAMS)

    private fun malformed(why: String): Nothing =
        throw ProtocolException("Malformed reply: $why", errorCode = ErrorCodes.INTERNAL_ERROR)

    companion object {
        private const val TAG = "RemoteOathClient"
        private const val TYPE_TOTP = "totp"
        private const val TYPE_HOTP = "hotp"
        private val ALGORITHMS = setOf("SHA1", "SHA256", "SHA512")

        /** Base of this client's JSON-RPC request IDs (others use 1M-4M). */
        const val BASE_REQUEST_ID = 5_000_000L

        /** Shared across instances so concurrent clients never reuse an ID. */
        private val nextId = AtomicLong(BASE_REQUEST_ID)

        private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

        /** RFC 4648 Base32 of [bytes], unpadded, into a zeroable CharArray. */
        fun base32Chars(bytes: ByteArray): CharArray {
            val out = CharArray((bytes.size * 8 + 4) / 5)
            var buffer = 0
            var bits = 0
            var o = 0
            for (b in bytes) {
                buffer = (buffer shl 8) or (b.toInt() and 0xff)
                bits += 8
                while (bits >= 5) {
                    out[o++] = ALPHABET[(buffer shr (bits - 5)) and 0x1f]
                    bits -= 5
                }
            }
            if (bits > 0) out[o++] = ALPHABET[(buffer shl (5 - bits)) and 0x1f]
            buffer = 0
            return out
        }
    }
}
