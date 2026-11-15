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

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The co-sign screen has one place that starts an append and one place that
 * opens the copy picker, so a response is checked against the media it was
 * scanned for, a running append is reattached, and a picker failure takes
 * the append's error path, whatever path leads there. A second call site
 * would bypass all three, and fails here.
 */
class CoSignAppendChokePointTest {

    private val source: String by lazy {
        val rel = "src/main/kotlin/com/automatethethings/xkey/ui/CoSignActivity.kt"
        val file = listOf(File(rel), File("app/$rel")).firstOrNull { it.isFile }
            ?: error("$rel not found from ${File(".").absolutePath}")
        file.readText()
    }

    /** The body of the function named [name]: from its declaration to the next private member. */
    private fun body(name: String): String {
        val start = source.indexOf("private fun $name(")
        assertTrue("$name is declared", start >= 0)
        val end = source.indexOf("\n    private ", start + 1).takeIf { it > 0 } ?: source.length
        return source.substring(start, end)
    }

    private fun count(needle: String, text: String = source) = Regex(Regex.escape(needle)).findAll(text).count()

    @Test
    fun `the copy picker opens only in launchCopyPicker`() {
        assertEquals(1, count("coSignedCopyLauncher.launch("))
        assertEquals(1, count("coSignedCopyLauncher.launch(", body("launchCopyPicker")))
    }

    @Test
    fun `an append starts only in appendQueuedResponse, as a process run`() {
        // The declaration, and one call inside appendQueuedResponse's MediaSaveRuns run.
        assertEquals(2, count("appendToMedia("))
        val starter = body("appendQueuedResponse")
        assertEquals(1, count("appendToMedia(", starter))
        assertTrue("the append runs in MediaSaveRuns", starter.indexOf("MediaSaveRuns.attach(") in 0 until starter.indexOf("appendToMedia("))
    }

    @Test
    fun `a response is queued only with its media binding`() {
        // Scanned (bound to the selection), or restored with its saved binding.
        assertEquals(2, count("queuedResponses.add("))
        assertEquals(1, count("queuedResponses.add(", body("restoreExchange")))
        assertEquals(1, count("queuedResponses.add(QueuedResponse(raw, media, currentSignatureData?.contentHash))", body("onResponseScanned")))
    }
}
