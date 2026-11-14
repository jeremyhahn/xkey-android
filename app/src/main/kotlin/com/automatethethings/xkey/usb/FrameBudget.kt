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

import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.transport.StreamMessageFraming
import org.json.JSONArray
import org.json.JSONObject

/**
 * The byte budget a USB method's result must keep so that its response, once
 * Noise encrypts it, still fits one [StreamMessageFraming] frame, and the
 * go-xkms `PageRequest`/`PageResponse` paging the stores answer within it.
 *
 * A response over the frame is not an error the peer sees: `writeMessage`
 * throws and the session ends without answering, so every result is sized here.
 */
internal object FrameBudget {

    /**
     * The Poly1305 tag Noise `ChaChaPoly` appends to every transport message
     * (`NoiseSession.TAG_SIZE`, which is private to the BLE package).
     */
    const val NOISE_TAG_SIZE = 16

    /**
     * What the JSON-RPC envelope adds around a result,
     * `{"id":<id>,"result":<result>}`, measured with the longest id.
     */
    private val ENVELOPE_SIZE: Int =
        Response.success(Long.MIN_VALUE, JSONObject()).toJson().size - JSONObject().toString().length

    private const val GENERATION_KEY = "generation"

    /**
     * The widest top-level generation member a response may carry,
     * `,"generation":18446744073709551615` (a Go `uint64` at its maximum).
     * [Response] carries the request's generation (go-xkms#128): the handler
     * echoes it in every answer to a request that sent one. The reserve is
     * kept for every response, with or without one, so a result sized
     * against [RESULT_BUDGET] fits the frame either way.
     */
    val GENERATION_RESERVE: Int =
        ",${JSONObject.quote(GENERATION_KEY)}:${ULong.MAX_VALUE}".toByteArray(Charsets.UTF_8).size

    /** The most bytes a serialized result may take. */
    val RESULT_BUDGET: Int =
        StreamMessageFraming.MAX_MESSAGE_SIZE - NOISE_TAG_SIZE - ENVELOPE_SIZE - GENERATION_RESERVE

    fun serializedSize(json: JSONObject): Int = json.toString().toByteArray(Charsets.UTF_8).size

    /**
     * The serialized size of a `PageResponse` result whose [key] array is
     * empty, with every number at its widest: what a page adds around its items.
     */
    fun pageOverhead(key: String): Int =
        serializedSize(pageResult(key, Int.MAX_VALUE, Int.MAX_VALUE, Int.MAX_VALUE, hasMore = false))

    /**
     * How many leading [items] fit, filled into the empty `[]` of a result
     * serializing to [baseSize] bytes, within [RESULT_BUDGET]. Each item costs
     * its JSON form plus a separating comma, written by the same org.json that
     * serializes the response, so its escaping counts.
     */
    fun fittingCount(items: List<Any>, baseSize: Int): Int {
        var size = baseSize
        var count = 0
        for (item in items) {
            val cost = elementSize(item) + if (count > 0) 1 else 0
            if (size + cost > RESULT_BUDGET) break
            size += cost
            count++
        }
        return count
    }

    /**
     * A `PageResponse` result carrying [items] under [key], for `PageRequest`
     * [page] (1-based, 0 = all) and [requestedSize] (0 = [defaultSize]).
     *
     * Page 0 answers the longest prefix that fits: `total` stays exact,
     * `has_more` says items were left out, and the caller reaches them by
     * paging. An explicit page is answered whole or refused with
     * [PageOverflowException], since `PageResponse` has no cursor to resume a
     * cut page from.
     */
    fun page(key: String, items: List<Any>, page: Int, requestedSize: Int, defaultSize: Int): JSONObject {
        if (page == 0) {
            // Measured with page_size at its widest and has_more false, the longer of its two values.
            val result = pageResult(key, 0, items.size, items.size, hasMore = false)
            val count = fittingCount(items, serializedSize(result))
            return result.apply {
                put(key, JSONArray(items.subList(0, count)))
                put("page_size", count)
                put("has_more", count < items.size)
            }
        }

        val pageSize = if (requestedSize > 0) requestedSize else defaultSize
        val offset = ((page - 1).toLong() * pageSize).coerceAtMost(items.size.toLong()).toInt()
        val end = minOf(items.size.toLong(), offset.toLong() + pageSize).toInt()
        val pageItems = items.subList(offset, end)
        val result = pageResult(key, page, pageSize, items.size, hasMore = end < items.size)
        val baseSize = serializedSize(result)
        result.put(key, JSONArray(pageItems))
        if (serializedSize(result) > RESULT_BUDGET) {
            // This many of the page's items fit: a smaller page_size has no more
            // digits, and has_more can only turn from false to true, a byte shorter.
            val fit = fittingCount(pageItems, baseSize)
            // Callers list only items that fit a page of their own, so the
            // suggestion is never a page_size of 0, which no page could follow.
            check(fit > 0) { "an item of page $page does not fit a page of its own" }
            throw PageOverflowException("page $page does not fit the frame; request a page_size of at most $fit")
        }
        return result
    }

    private fun pageResult(key: String, page: Int, pageSize: Int, total: Int, hasMore: Boolean) =
        JSONObject().apply {
            put(key, JSONArray())
            put("page", page)
            put("page_size", pageSize)
            put("total", total)
            put("has_more", hasMore)
        }

    /** What [item] adds as one element of a JSON array, before any separating comma. */
    private fun elementSize(item: Any): Int = JSONArray().put(item).toString().toByteArray(Charsets.UTF_8).size - 2
}

/** An explicit page whose items do not fit the frame whole; its message names a page_size that does. */
internal class PageOverflowException(message: String) : Exception(message)
