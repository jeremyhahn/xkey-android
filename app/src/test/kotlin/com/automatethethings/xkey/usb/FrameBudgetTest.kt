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

import com.automatethethings.xkey.password.PasswordEntryLimit
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.transport.MessageTooLargeException
import com.automatethethings.xkey.transport.StreamMessageFraming
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * Unit tests for [FrameBudget]: [FrameBudget.RESULT_BUDGET] is exactly what
 * [StreamMessageFraming] lets through once the envelope, the widest response
 * generation and the Noise tag are added, so a result sized against it fails
 * nowhere the session would not.
 */
class FrameBudgetTest {

    /** A result serializing to exactly [size] bytes. */
    private fun resultOfSize(size: Int): JSONObject {
        val padding = size - JSONObject().put("pad", "").toString().length
        return JSONObject().put("pad", "x".repeat(padding))
    }

    /** The widest generation member a response can carry, as go-xkms#128 / #10 writes it. */
    private val widestGeneration = ",\"generation\":${ULong.MAX_VALUE}"

    /** [response] with the widest generation spliced in by hand before its closing brace. */
    private fun withWidestGeneration(response: Response): ByteArray =
        (response.toJsonString().dropLast(1) + widestGeneration + "}").toByteArray(Charsets.UTF_8)

    /** Frames a ciphertext of [json]'s length, the Noise tag included. */
    private fun writeFramed(json: ByteArray) {
        val ciphertext = ByteArray(json.size + FrameBudget.NOISE_TAG_SIZE)
        StreamMessageFraming.writeMessage(ByteArrayOutputStream(), ciphertext)
    }

    /** A `names` page of one item, filled to serialize to exactly [FrameBudget.RESULT_BUDGET] bytes. */
    private fun pageOfBudget(): JSONObject {
        val empty = FrameBudget.serializedSize(FrameBudget.page("names", listOf(""), 1, 1, 1))
        val item = "x".repeat(FrameBudget.RESULT_BUDGET - empty)
        return FrameBudget.page("names", listOf(item), 1, 1, 1)
    }

    @Test
    fun `the generation reserve is the widest uint64 generation member`() {
        assertEquals(",\"generation\":18446744073709551615".length, FrameBudget.GENERATION_RESERVE)
    }

    @Test
    fun `RESULT_BUDGET plus the envelope, the generation reserve and the Noise tag is exactly the frame`() {
        val envelope = Response.success(Long.MIN_VALUE, JSONObject()).toJson().size - JSONObject().toString().length

        assertEquals(
            StreamMessageFraming.MAX_MESSAGE_SIZE,
            FrameBudget.RESULT_BUDGET + envelope + FrameBudget.GENERATION_RESERVE + FrameBudget.NOISE_TAG_SIZE
        )
    }

    @Test
    fun `the password store's entry limit is pinned to what the frame leaves a one-entry passwords page`() {
        // 65535 frame - 16 Noise tag - 37 envelope - 34 generation - 93 widest empty page.
        // A change to the budget fails here, where the entry limit's KDoc must follow.
        assertEquals(65_355, PasswordEntryLimit.MAX_ENTRY_SIZE)
        assertEquals(FrameBudget.RESULT_BUDGET - FrameBudget.pageOverhead("passwords"), PasswordEntryLimit.MAX_ENTRY_SIZE)
    }

    @Test
    fun `an entry at the limit on a one-entry page with the widest numbers and generation fills the frame`() {
        // Built by hand rather than through FrameBudget, at the widest page numbers PageRequest allows.
        val page = JSONObject().apply {
            put("passwords", JSONArray().put(resultOfSize(PasswordEntryLimit.MAX_ENTRY_SIZE)))
            put("page", Int.MAX_VALUE)
            put("page_size", Int.MAX_VALUE)
            put("total", Int.MAX_VALUE)
            put("has_more", false)
        }
        val json = withWidestGeneration(Response.success(Long.MIN_VALUE, page))

        assertEquals(StreamMessageFraming.MAX_MESSAGE_SIZE, json.size + FrameBudget.NOISE_TAG_SIZE)
        writeFramed(json)
    }

    @Test
    fun `a page filled exactly to RESULT_BUDGET under the longest id and the widest generation fills the frame`() {
        val page = pageOfBudget()
        assertEquals(FrameBudget.RESULT_BUDGET, FrameBudget.serializedSize(page))
        val json = withWidestGeneration(Response.success(Long.MIN_VALUE, page))

        assertEquals(StreamMessageFraming.MAX_MESSAGE_SIZE, json.size + FrameBudget.NOISE_TAG_SIZE)
        writeFramed(json)
    }

    @Test
    fun `a result one byte over RESULT_BUDGET with the widest generation is refused by the frame`() {
        val json = withWidestGeneration(Response.success(Long.MIN_VALUE, resultOfSize(FrameBudget.RESULT_BUDGET + 1)))

        assertThrows(MessageTooLargeException::class.java) { writeFramed(json) }
    }
}
