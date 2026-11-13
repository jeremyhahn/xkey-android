/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.auth

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every place in the app that raises a prompt -- a `BiometricPrompt`, a
 * full-screen notification, an approval prompt activity, the injected
 * user-verification prompt -- is one of the entry points listed here, and
 * each listed one goes through [PromptOwnership], the one prompt queue.
 *
 * The scan reads the main sources, so a new raiser anywhere fails this test
 * until it is listed, and it is listed only with the queue call that gates it
 * (its guard, which must stay in the file) or a written reason it cannot
 * raise while another prompt is ACTIVE.
 */
class PromptEntryPointsTest {

    /** What raises a prompt, as written in the source. */
    private enum class Raiser(val pattern: Regex) {
        BIOMETRIC_PROMPT(Regex("""\.authenticate\(\s*prompt""")),
        FULL_SCREEN_NOTIFICATION(Regex("""setFullScreenIntent\(""")),
        PROMPT_ACTIVITY(
            Regex("""(TransparentBiometricActivity|CryptoSigningActivity|CredentialSelectorActivity)::class\.java""")
        ),
        PROMPT_ACTIVITY_INTENT(Regex("""(TransparentBiometricActivity|CryptoSigningActivity)\.createIntent\(""")),
        USER_VERIFICATION_PROMPT(Regex("""userVerificationPrompt\??\.sign\(""")),
    }

    /**
     * One file's raisers: how many of each, and how the queue gates them.
     * Every [guards] string must appear in the file; [reason] says why that
     * guard keeps the raiser behind the ACTIVE entry.
     */
    private data class EntryPoint(
        val counts: Map<Raiser, Int>,
        val guards: List<String>,
        val reason: String,
    )

    private val registry: Map<String, EntryPoint> = mapOf(
        "crypto/BiometricHelper.kt" to EntryPoint(
            mapOf(Raiser.BIOMETRIC_PROMPT to 2),
            listOf("PromptOwnership.process.turn("),
            "both activity-bound prompts (and their wake notification, onTurn) run inside a queue turn; " +
                "KeystoreManager.sign, every Handler fallback and GetCredentialHandler reach the screen only here",
        ),
        "ui/TransparentBiometricActivity.kt" to EntryPoint(
            mapOf(Raiser.BIOMETRIC_PROMPT to 1, Raiser.PROMPT_ACTIVITY to 1),
            listOf("claim(requestId)", "PromptOwnership.process.accept("),
            "shows its prompt only for an id the process owner holds ACTIVE, launcher or wake-only alike",
        ),
        "ui/CryptoSigningActivity.kt" to EntryPoint(
            mapOf(Raiser.BIOMETRIC_PROMPT to 1, Raiser.PROMPT_ACTIVITY to 1),
            listOf("controller.attach"),
            "CryptoSigningController.attach prompts only while the signature-<id> entry is ACTIVE",
        ),
        "credential/ui/CredentialSelectorActivity.kt" to EntryPoint(
            mapOf(Raiser.BIOMETRIC_PROMPT to 1),
            listOf("PromptOwnership.process.enqueue("),
            "started by the system Credential Manager, it still takes a queue entry and prompts on its turn",
        ),
        "credential/CredentialPendingIntentHelper.kt" to EntryPoint(
            mapOf(Raiser.PROMPT_ACTIVITY to 2),
            emptyList(),
            "pending intents handed to the system Credential Manager; the activity they open waits its turn",
        ),
        "auth/BiometricNotificationHelper.kt" to EntryPoint(
            mapOf(Raiser.FULL_SCREEN_NOTIFICATION to 1, Raiser.PROMPT_ACTIVITY to 1),
            listOf("PromptOwnership.process.state("),
            "posts only under a key the process owner holds ACTIVE, and refuses any other",
        ),
        "auth/BiometricActivityLauncher.kt" to EntryPoint(
            mapOf(Raiser.PROMPT_ACTIVITY_INTENT to 2),
            listOf("pendingRequests.await", "pendingCryptoRequests.await"),
            "starts each prompt from its queue entry's turn (PendingAuthentications, PendingCryptoSignatures)",
        ),
        "protocol/Handler.kt" to EntryPoint(
            mapOf(Raiser.USER_VERIFICATION_PROMPT to 1),
            listOf("PromptOwnership.process.turn("),
            "local.verifyUser's injected prompt and its wake notification run inside a queue turn",
        ),
    )

    private val sourceRoot: File =
        listOf("src/main/kotlin", "app/src/main/kotlin").map(::File).first { it.isDirectory }
            .resolve("com/automatethethings/xkey")

    /** Raisers found in code lines (comments skipped), by file relative to the package root. */
    private fun scan(): Map<String, Map<Raiser, Int>> =
        sourceRoot.walkTopDown().filter { it.isFile && it.extension == "kt" }.mapNotNull { file ->
            val code = file.readLines().filterNot { line ->
                line.trimStart().let { it.startsWith("*") || it.startsWith("//") || it.startsWith("/*") }
            }
            val counts = Raiser.values().associateWith { raiser ->
                code.sumOf { raiser.pattern.findAll(it).count() }
            }.filterValues { it > 0 }
            if (counts.isEmpty()) null else file.relativeTo(sourceRoot).invariantSeparatorsPath to counts
        }.toMap()

    @Test
    fun everyPromptRaiserIsARegisteredEntryPoint() {
        val found = scan()
        val unlisted = found.keys - registry.keys
        assertTrue("prompt raisers outside the registry (route them through PromptOwnership): $unlisted", unlisted.isEmpty())
        found.forEach { (path, counts) ->
            assertEquals("raisers in $path changed; register each new one", registry.getValue(path).counts, counts)
        }
        val gone = registry.keys - found.keys
        assertTrue("registered entry points no longer found: $gone", gone.isEmpty())
    }

    @Test
    fun everyEntryPointKeepsTheQueueCallThatGatesIt() {
        registry.forEach { (path, entry) ->
            val text = sourceRoot.resolve(path).readText()
            entry.guards.forEach { guard ->
                assertTrue("$path raises a prompt without $guard: ${entry.reason}", guard in text)
            }
        }
    }
}
