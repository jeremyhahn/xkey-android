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

import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Cleanup scheduled into a cancellable scope goes through [launchCleanup]:
 * a default-start launch wrapping [kotlinx.coroutines.NonCancellable] cleanup
 * never runs when its scope is cancelled before it is dispatched.
 */
class CleanupChokePointTest {

    @Test
    fun `cleanup launched into an already cancelled scope runs to the end`() = runBlocking {
        val done = AtomicBoolean(false)
        val scope = CoroutineScope(Dispatchers.Default + Job()).apply { cancel() }
        scope.launchCleanup {
            delay(10)
            done.set(true)
        }.join()
        assertTrue("the cleanup ran past its suspension", done.get())
    }

    @Test
    fun `cleanup is never a default-start launch around NonCancellable work`() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val sources = root.walkTopDown().filter { it.extension == "kt" }.associate { it.path to it.readText() }
        val cleanups = sources.values.flatMap { nonCancellableFunctions(it) }.toSet()
        val strays = sources.flatMap { (path, text) -> unsafeLaunches(text, cleanups).map { "$path: $it" } }
        assertTrue("cleanup launched default-start; use launchCleanup: $strays", strays.isEmpty())
    }

    @Test
    fun `the check catches the forms it forbids`() {
        val text = """
            private suspend fun tearDown(session: NoiseSession) = withContext(NonCancellable) { }
            fun a() { scope.launch { withContext(NonCancellable) { zeroKeys(connection) } } }
            fun b() { scope.launch { tearDown(session) } }
            fun c() { scope.launch(Dispatchers.IO) { tearDown(session) } }
            fun d() { scope.launch(start = CoroutineStart.ATOMIC) { tearDown(session) } }
            fun e() { scope.launchCleanup { tearDown(session) } }
            fun f() { scope.launch { work() } }
        """
        val found = unsafeLaunches(text, nonCancellableFunctions(text).toSet())
        assertEquals(3, found.size)
    }

    private fun nonCancellableFunctions(text: String): List<String> =
        NON_CANCELLABLE_FUN.findAll(text).map { it.groupValues[1] }.toList()

    private fun unsafeLaunches(text: String, cleanups: Set<String>): List<String> =
        LAUNCH.findAll(text).filter { m ->
            val args = m.groupValues[1]
            val wrapsCleanup = m.groupValues[2].isNotEmpty() || m.groupValues[3] in cleanups
            wrapsCleanup && "ATOMIC" !in args && "UNDISPATCHED" !in args
        }.map { it.value.trim() }.toList()

    private companion object {
        /** A function whose whole body is NonCancellable. */
        val NON_CANCELLABLE_FUN = Regex(
            """fun\s+(\w+)\s*\([^{}=]*?\)\s*(?::[^{}=]*)?(?:=|\{)\s*withContext\(\s*NonCancellable"""
        )

        /** A launch, its arguments, and what its body starts with. */
        val LAUNCH = Regex(
            """\blaunch\s*(?:\(([^()]*(?:\([^()]*\)[^()]*)*)\))?\s*\{\s*(?:(withContext\(\s*NonCancellable)|(\w+)\s*\()"""
        )
    }
}
