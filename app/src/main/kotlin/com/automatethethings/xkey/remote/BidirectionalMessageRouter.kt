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
package com.automatethethings.xkey.remote

import android.util.Log
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.Response
import kotlinx.coroutines.CompletableDeferred
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Routes incoming decrypted messages to the appropriate handler.
 *
 * Incoming messages are classified as either:
 * - **Requests** (contain "method" field): routed to [RequestHandler]
 * - **Responses** (contain "result" or "error" field): routed to pending
 *   [CompletableDeferred] callbacks from outbound requests
 *
 * This enables bidirectional JSON-RPC over a single Noise-encrypted channel:
 * - `local.*` requests from the laptop are handled by [RequestHandler]
 * - Responses to `remote.*` requests from the phone are resolved by this router
 *
 * Thread safety: All mutable state uses [ConcurrentHashMap] for lock-free access.
 *
 * @param requestHandler The handler for incoming requests from the laptop.
 */
class BidirectionalMessageRouter(
    private val requestHandler: RequestHandler
) {
    companion object {
        private const val TAG = "BidirMessageRouter"
    }

    /** Pending outbound requests waiting for responses, keyed by request ID. */
    private val pendingResponses = ConcurrentHashMap<Long, CompletableDeferred<Response>>()

    /** Outbound request id counters, one per starting id, kept for this router's life. */
    private val requestIdCounters = ConcurrentHashMap<Long, AtomicLong>()

    /**
     * The counter for outbound request ids numbered from [base]. It lives as
     * long as this router, so a client replaced on the same router continues
     * the numbering and never reuses the id of a request whose late reply may
     * still arrive.
     */
    fun requestIds(base: Long): AtomicLong = requestIdCounters.computeIfAbsent(base) { AtomicLong(it) }

    /**
     * Processes an incoming decrypted message.
     *
     * Determines whether the message is a request or response and routes accordingly.
     *
     * @param plaintext The decrypted JSON-RPC message bytes.
     * @return The response bytes to send back (for requests), or null (for responses).
     */
    suspend fun processMessage(plaintext: ByteArray): ByteArray? {
        val json = String(plaintext, Charsets.UTF_8)
        val obj = JSONObject(json)

        // Check if this is a response (has "result" or "error" but no "method")
        val hasMethod = obj.has("method") && !obj.isNull("method")
        val hasResult = obj.has("result") && !obj.isNull("result")
        val hasError = obj.has("error") && !obj.isNull("error")

        if (!hasMethod && (hasResult || hasError)) {
            // This is a response to one of our outbound requests
            handleIncomingResponse(json)
            return null // No response to send back
        }

        // This is a request from the laptop - delegate to RequestHandler
        return requestHandler.handleRawRequest(plaintext)
    }

    /**
     * Registers a pending response for an outbound request.
     *
     * @param requestId The JSON-RPC request ID.
     * @param deferred The deferred to complete when the response arrives.
     */
    fun registerPendingResponse(requestId: Long, deferred: CompletableDeferred<Response>) {
        pendingResponses[requestId] = deferred
    }

    /**
     * Removes a pending response registration (e.g., on timeout or cancellation).
     *
     * @param requestId The JSON-RPC request ID.
     */
    fun removePendingResponse(requestId: Long) {
        pendingResponses.remove(requestId)
    }

    /**
     * Routes an incoming response to the matching pending request.
     */
    private fun handleIncomingResponse(json: String) {
        try {
            val response = Response.fromJson(json)
            val deferred = pendingResponses.remove(response.id)
            if (deferred != null) {
                Log.d(TAG, "Routing response for request id=${response.id}")
                deferred.complete(response)
            } else {
                Log.w(TAG, "No pending request for response id=${response.id}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse incoming response", e)
        }
    }

    /**
     * Cancels all pending requests with an error.
     *
     * Call this when the connection is lost.
     */
    fun cancelAllPending() {
        val entries = pendingResponses.entries.toList()
        pendingResponses.clear()
        for ((id, deferred) in entries) {
            deferred.complete(
                Response.error(id, ErrorCodes.INTERNAL_ERROR, "Connection lost")
            )
        }
        if (entries.isNotEmpty()) {
            Log.d(TAG, "Cancelled ${entries.size} pending requests")
        }
    }
}
