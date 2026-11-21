/*
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.automatethethings.xkey.ui

import android.app.Application
import android.net.Uri
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.XmpFixtures
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

/**
 * The exchange record: a written copy takes the co-signed media's place in
 * every part that names it, and the record survives its saved form whole.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class CoSignExchangeTest {

    private val source = Uri.parse("content://media/source.png")
    private val target = Uri.parse("content://media/copy.png")
    private val data = ContentAuthenticityData.fromJsonString(XmpFixtures.json("a".repeat(64)))

    private fun copyOf(from: Uri) = PendingCoSignedCopy(File("staged.png"), "Witness", "fp", data, from)

    /** Every Uri field the record has, set to [source]. */
    private fun everyFieldOnSource() = CoSignExchange(
        media = source,
        scan = ScanTarget(source, "a".repeat(64)),
        queued = listOf(QueuedResponse("raw", source, "a".repeat(64))),
        runningAppend = "append",
        pendingCopy = copyOf(source),
        runningCopy = RunningCoSignedCopy("copy", source, copyOf(source))
    )

    @Test
    fun `a rebind leaves no field on the source`() {
        val moved = everyFieldOnSource().rebind(source, target)
        assertFalse(moved.toString(), moved.toString().contains(source.toString()))
        assertTrue(moved.toString().contains(target.toString()))
    }

    @Test
    fun `a written copy moves the selection, the open scan and the queue to it`() {
        val run = RunningCoSignedCopy("copy", target, copyOf(source))
        val ended = CoSignExchange(
            media = source,
            scan = ScanTarget(source, "h"),
            queued = listOf(QueuedResponse("raw", source, "h")),
            runningCopy = run
        ).on(CoSignExchange.Event.CopyEnded(written = true))
        assertEquals(target, ended.media)
        assertEquals(target, ended.scan?.media)
        assertEquals(target, ended.queued.single().media)
        assertEquals(null, ended.runningCopy)
    }

    @Test
    fun `a failed copy leaves the media bound to the source`() {
        val ended = CoSignExchange(media = source, runningCopy = RunningCoSignedCopy("copy", target, copyOf(source)))
            .on(CoSignExchange.Event.CopyEnded(written = false))
        assertEquals(source, ended.media)
        assertEquals(null, ended.runningCopy)
    }

    @Test
    fun `the saved form restores the whole record`() {
        val exchange = everyFieldOnSource()
        assertEquals(exchange.toJson(), CoSignExchange.fromJson(exchange.toJson()).toJson())
    }

    @Test
    fun `an unreadable saved form restores an empty exchange`() {
        assertEquals(CoSignExchange(), CoSignExchange.fromJson("{not json"))
    }
}
