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
        // Queued only by the exchange: bound to what the scan began for, or restored with its saved binding.
        assertEquals("the declaration and two constructions", 3, Regex("""\bQueuedResponse\(""").findAll(source).count())
        assertEquals(1, count("QueuedResponse(event.raw, scan?.media, scan?.contentHash)"))
        assertEquals(1, count("QueuedResponse(q.getString(\"raw\"), q.uri(\"media\")"))
        // Bound to what the scan began for (kept across a recreation), never to what shows when it returns.
        assertEquals(1, count("CoSignExchange.Event.ScanStarted("))
        assertEquals(1, count("CoSignExchange.Event.ScanStarted(", body("startResponseScan")))
        assertEquals(1, count("responseScanner.launch("))
        assertEquals(1, count("responseScanner.launch(", body("startResponseScan")))
    }

    @Test
    fun `an append is refused, not unchecked, when the hash it was scanned for is missing`() {
        assertEquals(1, count("private fun appendToMedia(context: Context, uri: Uri, entry: SignatureEntry, expectedHash: String)"))
        assertEquals(0, count("expectedHash != null"))
    }

    /**
     * The exchange (selected media, open scan, queued responses, running
     * append, copy to place, copy writing) is one immutable record, saved and
     * restored whole, and replaced only in transition: a field kept apart, or
     * written anywhere else, is restored out of step with the rest.
     */
    @Test
    fun `the exchange is written only in transition`() {
        for (name in listOf("selectedUri", "responseScanFor", "queuedResponses", "runningAppend", "pendingCopy", "runningCopy")) {
            val screen = source.substring(source.indexOf("class CoSignActivity "))
            assertEquals("$name is kept apart from the exchange", 0, Regex("""\b(var|val) $name\b""").findAll(screen).count())
        }
        val writes = Regex("""\bexchange = """).findAll(source).count()
        assertEquals("declared, then replaced in one place", 2, writes)
        assertEquals(1, Regex("""\bexchange = """).findAll(body("transition")).count())
        assertEquals(1, count("private var exchange = CoSignExchange()"))
        val start = source.indexOf("internal data class CoSignExchange(")
        assertTrue("the exchange record is declared", start >= 0)
        val record = source.substring(start, source.indexOf("\n}\n", start))
        for (mutable in listOf("var ", "Mutable", "ArrayList")) {
            assertEquals("the exchange record holds no '$mutable'", 0, count(mutable, record))
        }
        assertEquals("saved whole, under one key", 1, count("putString(STATE_EXCHANGE"))
    }

    /**
     * The changed-content guard hashes the staged payload with the signer's
     * own function: the hash its signature data names can be kept on other
     * content, so it alone proves nothing.
     */
    @Test
    fun `the append checks the payload's own hash, as the signer computes it`() {
        val guard = body("appendToMedia")
        // Streamed, as the Share-sheet signer hashes: no size cap signing does not apply.
        assertEquals(1, count("MediaHasher.hashStreamed(", guard))
        assertEquals(0, count("AutoSignHash.contentHash", guard))
        assertTrue("checked before anything is appended", guard.indexOf("MediaHasher.hashStreamed(") < guard.indexOf("appendSignature("))
    }

    /**
     * A screen reads a save run only through MediaSaveRuns.outcome, which tells
     * the screen's own cancellation from the run's end: reading the run's
     * Deferred directly can take the cancellation for the run's failure and
     * drop a finished run's result.
     */
    @Test
    fun `a save run is read only through MediaSaveRuns outcome`() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val users = root.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .map { it to it.readText() }.filter { (_, text) -> "MediaSaveRuns.attach(" in text }.toList()
        assertTrue("CoSignActivity starts runs", users.any { it.first.name == "CoSignActivity.kt" })
        for ((file, text) in users) {
            val names = Regex("""val (\w+) = MediaSaveRuns\.attach\(""").findAll(text).map { it.groupValues[1] }.toList()
            assertEquals("${file.name}: every run is named", count("MediaSaveRuns.attach(", text), names.size)
            for (name in names) {
                assertEquals("${file.name}: $name read directly", 0, count("$name.await(", text) + count("$name.join(", text) + count("$name.isCompleted", text))
                assertTrue("${file.name}: $name read through outcome", count("MediaSaveRuns.outcome($name, lifecycle)", text) >= 1)
            }
        }
    }
}
