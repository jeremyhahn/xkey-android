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

package com.automatethethings.xkey.protocol

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.BiometricAuthMode
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.io.File
import java.util.Base64
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * A request that waits in an approval prompt while the key it uses is
 * deleted never runs crypto with that key (#255 review, ruling 554).
 *
 * The dispatch gate checks the key once, before the handler; a sign then
 * waits in its prompt, and a delete can report success meanwhile. Every
 * crypto call of a user key in the protocol handlers runs inside
 * KeyPolicyStore.withUsableKey, which rechecks the key under the lock every
 * delete takes. The sweep below keeps a new crypto call from bypassing it.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SignAfterDeleteTest {

    private lateinit var keystore: KeystoreManager
    private lateinit var biometricLauncher: BiometricActivityLauncher
    private lateinit var handler: RequestHandler
    private val approval = CompletableDeferred<Unit>()
    @Volatile private var deleted = false

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)

        // The key's tombstone appears once its delete has reported success.
        val policies = mockk<KeyPolicyDao>(relaxed = true)
        coEvery { policies.deletion(any()) } answers {
            if (deleted) mockk<KeyDeletionEntity>(relaxed = true) else null
        }
        coEvery { policies.policyRow(any()) } returns null
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns mockk(relaxed = true) {
            every { keyPolicyDao() } returns policies
        }
        Dispatchers.setMain(UnconfinedTestDispatcher())

        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        keystore = mockk(relaxed = true)
        every { keystore.soleKind(any()) } returns com.automatethethings.xkey.crypto.UserKeyKind.CREDENTIAL
        coEvery { keystore.signApproved(any(), any(), any(), any()) } returns ByteArray(64) { 7 }

        // The prompt stays open until the test approves it.
        biometricLauncher = mockk(relaxed = true)
        coEvery { biometricLauncher.requestAuthentication(any(), any(), any(), any(), any()) } coAnswers {
            approval.await()
        }

        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = biometricLauncher,
            sessionAuthManager = SessionAuthManager(clock = { 0L }),
        )
        handler.updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.REQUIRED,
                authMode = BiometricAuthMode.PER_SESSION,
            )
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Test
    fun `a sign approved after its key was deleted is refused before any signing`() = runTest {
        val pending = async { sign() }
        runCurrent()

        // The user deletes the key while the sign's prompt is open, and the
        // delete reports success; then the prompt is approved.
        deleted = true
        approval.complete(Unit)
        val response = pending.await()

        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.error?.code)
        coVerify(exactly = 0) { keystore.signApproved(any(), any(), any(), any()) }
    }

    @Test
    fun `a sign approved while its key is still there signs`() = runTest {
        val pending = async { sign() }
        runCurrent()
        approval.complete(Unit)

        assertEquals(null, pending.await().error)
        coVerify(exactly = 1) { keystore.signApproved(any(), any(), any(), any()) }
    }

    @Test
    fun `every crypto call of a user key in the protocol handlers runs inside withUsableKey`() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val crypto = Regex(
            """keystoreManager\.(sign|signWithoutBiometric|signWithAlgorithm|rsaDecrypt\w*|decrypt\w*|encrypt\w*|symmetric\w*|computeHMAC\w*|performECDH|ecdh\w*)\(""" +
                """|requestCryptoSignature(OnTurn)?\(|approvals\.sign\(|SoftwareKeyOps\.(aesGcm\w*|hmac|sign\w*|ecdh\w*)\("""
        )
        // The gates: the use gate, and its prompt-ordered forms (#255 review r4).
        val gates = listOf("withUsableKey(", "withUsableGeneralKey(", "withKeyUseOnTurn(", "withGeneralKeyUseOnTurn(", "withKeyUseInOneTurn(")
        // CosignApprovalPrompts is the co-sign prompt itself: its caller's
        // `approvals.sign(` is swept here instead.
        val bypasses = File(root, "com/automatethethings/xkey/protocol").listFiles { f -> f.extension == "kt" && f.name != "CosignApprovalPrompts.kt" }!!
            .flatMap { file ->
                val lines = file.readLines()
                lines.mapIndexedNotNull { i, line ->
                    val code = line.substringBefore("//")
                    // withUsableGeneralKey is the key uses' gate: it runs withUsableKey (asserted below).
                    if (!crypto.containsMatchIn(code) || gates.any { it in code }) return@mapIndexedNotNull null
                    // A prompt's call on the line after its withKeyUseOnTurn
                    // (or the general-key form) opens.
                    if (lines.getOrNull(i - 1)?.contains("UseOnTurn(") == true) return@mapIndexedNotNull null
                    // A software key's crypto runs in the use block of
                    // withUsableSoftwareKey, the gate's software-key choke point.
                    if (lines.getOrNull(i - 1)?.trimEnd()?.endsWith("{ sw ->") == true &&
                        "withUsableSoftwareKey(" in lines[i - 1]
                    ) return@mapIndexedNotNull null
                    // The user-verification key is the app's own, never a peer's key to delete.
                    if (lines.getOrNull(i + 1)?.contains("\"user-verification\"") == true) return@mapIndexedNotNull null
                    // A per-operation prompt in a CryptoObjectSigner runs only where the signer is passed in, checked below.
                    if ((maxOf(0, i - 3) until i).any { "CryptoObjectSigner {" in lines[it] }) return@mapIndexedNotNull null
                    "${file.name}:${i + 1}"
                }
            }
        assertEquals(emptyList<String>(), bypasses)
        // Every call handed the CryptoObjectSigner runs in a gate opened at most 10 lines above, or forwards a helper's own parameter.
        val handlerLines = File(root, "com/automatethethings/xkey/protocol/Handler.kt").readLines()
        val ungatedSigner = handlerLines.indices.filter { i ->
            val code = handlerLines[i].substringBefore("//")
            Regex("""\(\s*[^)]*\bcryptoObjectSigner\)|,\s*cryptoObjectSigner\s*$""").containsMatchIn(code) &&
                "fun " !in code &&
                (maxOf(0, i - 10) until i).none { j -> gates.any { it in handlerLines[j] } } &&
                (maxOf(0, i - 15) until i).none { j -> "fun " in handlerLines[j] && "cryptoObjectSigner: " in handlerLines.subList(j, i).joinToString("") }
        }.map { "Handler.kt:${it + 1}" }
        assertEquals("a CryptoObjectSigner used outside a gate", emptyList<String>(), ungatedSigner)
        val handler = File(root, "com/automatethethings/xkey/protocol/Handler.kt").readText()
        val gate = handler.substringAfter("fun <T> withUsableGeneralKey(").substringBefore("\n    }\n")
        assertTrue("withUsableGeneralKey resolves the id's key", "ownedKeyKind(" in gate)
        assertTrue("withUsableGeneralKey runs inside withUsableKey", "keyPolicyStore.withUsableKey(" in gate)
        val onTurn = handler.substringAfter("fun <T> withGeneralKeyUseOnTurn(").substringBefore("\n    }\n")
        assertTrue("withGeneralKeyUseOnTurn resolves the id's key", "ownedKeyKind(" in onTurn)
        assertTrue("withGeneralKeyUseOnTurn reserves on the turn", "keyPolicyStore.withKeyUseOnTurn(" in onTurn)
        // The co-sign prompt hands its caller's reserve to the on-turn launcher call.
        val prompts = File(root, "com/automatethethings/xkey/protocol/CosignApprovalPrompts.kt").readText()
        val sign = prompts.substringAfter("suspend fun sign(").substringBefore("\n    }\n")
        assertTrue("the co-sign prompt reserves on its turn", "requestCryptoSignatureOnTurn(" in sign && "onTurn()" in sign)
        assertFalse("the co-sign prompt signs eagerly", "requestCryptoSignature(" in sign)
    }

    /**
     * No key use holds its reservation while it waits for the prompt queue
     * (#255 review r4): a prompt that signs with a user key runs through
     * withKeyUseOnTurn or withKeyUseInOneTurn, which reserve the use only
     * once the turn is held, never inside withUsableKey, withUsableGeneralKey,
     * withUsableSoftwareKey or withKeyMaterial (#255 review r5: the co-sign).
     */
    @Test
    fun `no prompt waits for the queue inside withUsableKey`() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val prompting = Regex(
            """requestCryptoSignature(OnTurn)?\(|requestAuthentication\(|inOneTurn\(|keystoreManager\.sign\(""" +
                """|approvals\.(sign|approve)\(|BiometricHelper\.\w+\("""
        )
        val inside = root.walkTopDown().filter { it.extension == "kt" }.flatMap { file ->
            val text = file.readText()
            Regex("""(withUsableKey|withUsableGeneralKey|withUsableSoftwareKey|withKeyMaterial)\([^)]*\)\s*\{""").findAll(text).mapNotNull { open ->
                // The block's body, up to its matching brace.
                var depth = 0
                var end = open.range.last
                for (j in open.range.last until text.length) {
                    when (text[j]) {
                        '{' -> depth++
                        '}' -> if (--depth == 0) { end = j; break }
                    }
                }
                val body = text.substring(open.range.last, end)
                if (prompting.containsMatchIn(body)) {
                    "${file.name}:${text.substring(0, open.range.first).count { it == '\n' } + 1}"
                } else null
            }
        }.toList()
        assertEquals(emptyList<String>(), inside)
    }

    private suspend fun sign(): Response {
        val params = JSONObject()
            .put("credentialId", "credential-1")
            .put("dataHash", Base64.getEncoder().encodeToString(ByteArray(32) { 1 }))
            .put("userVerificationRequired", true)
        val raw = withContext(
            RequestHandler.servedConnection(SessionBindingProvider { null }, null, "usb:one")
        ) {
            handler.handleRawRequest(Request(id = 1, method = MethodNames.SIGN, params = params).toJson())
        }
        return Response.fromJson(raw)
    }
}
