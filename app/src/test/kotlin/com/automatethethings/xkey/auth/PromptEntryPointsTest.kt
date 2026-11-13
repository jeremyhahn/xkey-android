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
        USER_VERIFICATION_PROMPT(Regex("""userVerificationPrompt\??\.(sign\(|let\b)""")),
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
        "credential/handler/CredentialPendingIntentHelper.kt" to EntryPoint(
            mapOf(Raiser.PROMPT_ACTIVITY to 2),
            listOf("PromptOwnership.queued("),
            "pending intents handed to the system Credential Manager carry the queue key the activity they open " +
                "enqueues under, and it prompts only on that key's turn",
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
            assertTrue("$path is registered with no PromptOwnership guard: ${entry.reason}", entry.guards.isNotEmpty())
            val text = sourceRoot.resolve(path).readText()
            entry.guards.forEach { guard ->
                assertTrue("$path raises a prompt without $guard: ${entry.reason}", guard in text)
            }
        }
    }

    /**
     * The approval prompt activity starts only on a queue turn: every
     * `TransparentBiometricActivity.createIntent` in the main sources is
     * built inside a `pendingRequests.await` launch, and that await enqueues
     * the request with [PromptOwnership] before it launches anything. A prompt
     * started from anywhere else (#177's co-sign kept a queue of its own) is
     * shown beside the ACTIVE one, and the two swallow each other.
     */
    @Test
    fun everyApprovalPromptActivityStartsOnAQueueTurn() {
        val launch = Regex("""TransparentBiometricActivity\.createIntent\(""")
        val bypasses = sourceRoot.walkTopDown().filter { it.isFile && it.extension == "kt" }.flatMap { file ->
            val code = file.readLines().filterNot { line ->
                line.trimStart().let { it.startsWith("*") || it.startsWith("//") || it.startsWith("/*") }
            }.joinToString("\n")
            val path = file.relativeTo(sourceRoot).invariantSeparatorsPath
            launch.findAll(code).filterNot { match ->
                // The function the launch is written in, up to the launch
                "pendingRequests.await" in code.substring(0, match.range.first).substringAfterLast("fun ")
            }.map { path }
        }.toList()
        assertTrue("TransparentBiometricActivity started outside a PromptOwnership turn: $bypasses", bypasses.isEmpty())

        val await = sourceRoot.resolve("auth/BiometricActivityLauncher.kt").readText()
            .substringAfter("class PendingAuthentications").substringAfter("suspend fun await(")
            .substringBefore("fun complete(")
        val enqueued = await.indexOf("prompts.enqueue(")
        val launched = await.indexOf("launch(id.toString())")
        assertTrue("PendingAuthentications.await launches without a queue entry", enqueued in 0 until launched)
    }

    /**
     * An approval can wait a minute for the owner, and the stored key it was
     * asked for can be deleted, re-policied or replaced under its id while it
     * does. Every handler operation that reads a stored key row and uses a
     * key after its approval runs the one post-approval check,
     * `revalidateApprovedKey`, between the last approval and the first use,
     * and that check compares what makes the row the same key.
     */
    @Test
    fun everyApprovalGatedKeyUseRevalidatesTheKeyAfterTheApproval() {
        val code = sourceRoot.resolve("protocol/Handler.kt").readLines().filterNot { line ->
            line.trimStart().let { it.startsWith("*") || it.startsWith("//") || it.startsWith("/*") }
        }.joinToString("\n")
        val approval = Regex("""requestAuthentication\(|\.approve\(|requireUserPresenceForAttestation\(|requestCryptoSignature\(""")
        val rowRead = Regex("""getByKeyId\(|\.getAll\(\)""")
        val keyUse = Regex("""signWithAlgorithm\(|withKeyLock\(""")
        val functions = Regex("""\n    (?:private |internal |override )?(?:suspend )?fun (\w+)""").findAll(code).toList()
        val unchecked = functions.mapIndexedNotNull { i, fn ->
            val body = code.substring(fn.range.first, functions.getOrNull(i + 1)?.range?.first ?: code.length)
            val lastApproval = approval.findAll(body).lastOrNull() ?: return@mapIndexedNotNull null
            if (!rowRead.containsMatchIn(body)) return@mapIndexedNotNull null
            val use = keyUse.find(body, lastApproval.range.last) ?: return@mapIndexedNotNull null
            val between = body.substring(lastApproval.range.last, use.range.first)
            if ("revalidateApprovedKey(" in between) null else fn.groupValues[1]
        }
        assertTrue("approval-gated key use without revalidateApprovedKey: $unchecked", unchecked.isEmpty())

        val check = code.substringAfter("fun revalidateApprovedKey(", "").substringBefore("\n    }")
        listOf("getByKeyId(", "isSameKeyAs(").forEach {
            assertTrue("revalidateApprovedKey does not call $it", it in check)
        }
        val same = code.substringAfter("fun KeyEntity.isSameKeyAs(", "").substringBefore("\n}")
        listOf("id ==", "keyType ==", "algorithm ==", "policyRevision ==", "publicKeyDer", "rpId ==").forEach {
            assertTrue("isSameKeyAs does not compare $it", it in same)
        }
    }

    /** What lets a queue entry go from an activity's teardown (a media player's release is not one). */
    private val releases = Regex("""PromptOwnership\.process\.(end|settle|expire)\(|controller\??\.release\(""")

    /**
     * A biometric ceremony outlives a configuration change, so an activity
     * whose onDestroy lets its queue entry go does so only when it is not
     * being recreated: otherwise a rotation hands the screen to the next
     * approval while its own prompt is still up.
     */
    @Test
    fun noActivityReleasesItsQueueEntryOnAConfigurationChange() {
        val activities = sourceRoot.walkTopDown().filter { it.isFile && it.name.endsWith("Activity.kt") }.toList()
        assertTrue("no activities scanned", activities.isNotEmpty())
        val unguarded = activities.mapNotNull { file ->
            val body = onDestroyBody(file.readText()) ?: return@mapNotNull null
            val code = body.lines().filterNot { it.trimStart().startsWith("//") }.joinToString("\n")
            val path = file.relativeTo(sourceRoot).invariantSeparatorsPath
            if (releases.containsMatchIn(code) && "isChangingConfigurations" !in code) path else null
        }
        assertTrue("onDestroy releases a prompt's queue entry on a configuration change: $unguarded", unguarded.isEmpty())
    }

    /** The braces-balanced body of `override fun onDestroy()`, or null when there is none. */
    private fun onDestroyBody(text: String): String? {
        val start = Regex("""override fun onDestroy\(\)\s*\{""").find(text) ?: return null
        var depth = 1
        var i = start.range.last + 1
        while (i < text.length && depth > 0) {
            when (text[i]) {
                '{' -> depth++
                '}' -> depth--
            }
            i++
        }
        return text.substring(start.range.last + 1, i - 1)
    }
}
