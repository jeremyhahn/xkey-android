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
package com.automatethethings.xkey.usb

import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.protocol.TransportMethods
import com.automatethethings.xkey.storage.SealStore
import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64
import kotlin.coroutines.cancellation.CancellationException

/**
 * The seal-store methods go-xkms proxies over USB, with the request and
 * response shapes of go-xkms `pkg/api/transport/types.go` verbatim. Go `[]byte`
 * fields (`secret`) travel as standard base64.
 *
 * Secrets are sealed by [SealStore] under a Keystore key; a plaintext secret
 * exists only in a `SealStoreGet` response, so `SealStorePut` refuses a secret
 * whose response would not fit one frame ([FrameBudget.RESULT_BUDGET]).
 */
class SealStoreMethods(private val store: SealStore) : TransportMethods {

    companion object {
        const val SEAL_STORE_PUT = "SealStorePut"
        const val SEAL_STORE_GET = "SealStoreGet"
        const val SEAL_STORE_DELETE = "SealStoreDelete"
        const val SEAL_STORE_LIST = "SealStoreList"
        const val SEAL_STORE_RESEAL = "SealStoreReseal"
        const val SEAL_STORE_STATUS = "SealStoreStatus"

        private val METHODS = setOf(
            SEAL_STORE_PUT, SEAL_STORE_GET, SEAL_STORE_DELETE,
            SEAL_STORE_LIST, SEAL_STORE_RESEAL, SEAL_STORE_STATUS
        )

        /** `PageRequest.page_size` default when a page is asked for without one. */
        const val DEFAULT_PAGE_SIZE = 25

        /**
         * Longest name `SealStorePut` accepts, in UTF-8 bytes. Every stored name
         * comes back in `SealStoreList` and `SealStoreStatus`, which must each
         * fit one frame ([FrameBudget.RESULT_BUDGET]). At 1 KiB even a name
         * whose every byte JSON writes as a six-byte Unicode escape serializes to
         * about 6 KiB, so one response always carries several names, and no name
         * is too long ever to be listed.
         */
        const val MAX_NAME_BYTES = 1024
    }

    /** A request the store refuses as malformed. */
    private class InvalidParamsException(message: String) : Exception(message)

    /** A request naming a secret that does not exist. */
    private class NotFoundException(message: String) : Exception(message)

    /** A stored secret whose `SealStoreGet` response would not fit one frame. */
    private class SecretTooLargeException : Exception("sealed secret does not fit the frame")

    override fun handles(method: String): Boolean = method in METHODS

    override suspend fun handle(request: Request): Response {
        return try {
            val params = request.params ?: JSONObject()
            val result = when (request.method) {
                SEAL_STORE_PUT -> put(params)
                SEAL_STORE_GET -> get(params)
                SEAL_STORE_DELETE -> delete(params)
                SEAL_STORE_LIST -> list(params)
                SEAL_STORE_RESEAL -> reseal(params)
                SEAL_STORE_STATUS -> status()
                else -> return Response.error(
                    request.id, ErrorCodes.METHOD_NOT_FOUND, "Unknown method: ${request.method}"
                )
            }
            Response.success(request.id, result)
        } catch (e: CancellationException) {
            throw e
        } catch (e: InvalidParamsException) {
            Response.error(request.id, ErrorCodes.INVALID_PARAMS, e.message ?: "invalid params")
        } catch (e: PageOverflowException) {
            Response.error(request.id, ErrorCodes.INVALID_PARAMS, e.message ?: "page does not fit the frame")
        } catch (e: NotFoundException) {
            Response.error(request.id, ErrorCodes.KEY_NOT_FOUND, e.message ?: "not found")
        } catch (e: SecretTooLargeException) {
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, e.message ?: "sealed secret does not fit the frame")
        } catch (e: Exception) {
            // Never echo the cause: it may carry secret material.
            Response.error(request.id, ErrorCodes.INTERNAL_ERROR, "seal store operation failed")
        }
    }

    private suspend fun put(params: JSONObject): JSONObject {
        val name = params.requireName()
        if (name.toByteArray(Charsets.UTF_8).size > MAX_NAME_BYTES) {
            throw InvalidParamsException("name exceeds $MAX_NAME_BYTES bytes")
        }
        val encoded = params.string("secret") ?: throw InvalidParamsException("secret is required")
        val secret = try {
            Base64.getDecoder().decode(encoded)
        } catch (e: IllegalArgumentException) {
            throw InvalidParamsException("secret must be base64")
        }
        try {
            // Android's org.json writes '/' as "\/", so a base64 secret can
            // serialize to twice its length: measure the response Get would send.
            if (!fitsFrame(getResult(name, secret))) {
                throw InvalidParamsException(
                    "secret does not fit a SealStoreGet response of ${FrameBudget.RESULT_BUDGET} bytes"
                )
            }
            store.put(name, secret)
        } finally {
            secret.fill(0)
        }
        return JSONObject()
    }

    private suspend fun get(params: JSONObject): JSONObject {
        val name = params.requireName()
        val secret = store.get(name) ?: throw NotFoundException("sealed secret not found")
        val result = try {
            getResult(name, secret)
        } finally {
            secret.fill(0)
        }
        // Put now refuses such a secret; only one stored before that, or by another path, gets here.
        if (!fitsFrame(result)) throw SecretTooLargeException()
        return result
    }

    /** `SealStoreGetResponse` for [secret] under [name]: what Get answers and Put measures. */
    private fun getResult(name: String, secret: ByteArray): JSONObject = JSONObject().apply {
        put("name", name)
        put("secret", Base64.getEncoder().encodeToString(secret))
    }

    private fun fitsFrame(result: JSONObject): Boolean =
        FrameBudget.serializedSize(result) <= FrameBudget.RESULT_BUDGET

    private suspend fun delete(params: JSONObject): JSONObject {
        val name = params.requireName()
        if (!store.delete(name)) throw NotFoundException("sealed secret not found")
        return JSONObject()
    }

    /** `SealStoreListResponse` for `PageRequest` [params], paged within the frame by [FrameBudget.page]. */
    private suspend fun list(params: JSONObject): JSONObject {
        val names = store.list()
        val page = params.nonNegativeInt("page") ?: 0
        val requestedSize = params.nonNegativeInt("page_size") ?: 0
        return FrameBudget.page("names", names, page, requestedSize, DEFAULT_PAGE_SIZE)
    }

    private suspend fun reseal(params: JSONObject): JSONObject {
        val name = params.requireName()
        if (!store.reseal(name)) throw NotFoundException("sealed secret not found")
        return JSONObject()
    }

    /**
     * `SealStoreStatusResponse`. `secret_count` is exact; `secret_names` is cut
     * to the longest prefix that fits the frame, and go-xkms has no field that
     * says it was cut.
     */
    private suspend fun status(): JSONObject {
        val names = store.list()
        val result = JSONObject().apply {
            put("available", true)
            put("sealer_id", SealStore.SEALER_ID)
            put("secret_count", names.size)
        }
        if (names.isEmpty()) return result
        result.put("secret_names", JSONArray())
        val count = FrameBudget.fittingCount(names, FrameBudget.serializedSize(result))
        if (count == 0) result.remove("secret_names")
        else result.put("secret_names", JSONArray(names.subList(0, count)))
        return result
    }

    private fun JSONObject.requireName(): String {
        val name = string("name")
        if (name.isNullOrEmpty()) throw InvalidParamsException("name is required")
        return name
    }

    /** An optional non-negative integer field, or null when absent. */
    private fun JSONObject.nonNegativeInt(key: String): Int? {
        if (!has(key) || isNull(key)) return null
        val value = get(key)
        if (value !is Int || value < 0) throw InvalidParamsException("$key must be a non-negative integer")
        return value
    }

    private fun JSONObject.string(key: String): String? {
        if (!has(key) || isNull(key)) return null
        return get(key) as? String ?: throw InvalidParamsException("$key must be a string")
    }
}
