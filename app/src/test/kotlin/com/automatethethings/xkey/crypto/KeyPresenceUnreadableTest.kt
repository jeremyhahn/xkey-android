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
package com.automatethethings.xkey.crypto

import android.content.Context
import android.content.SharedPreferences
import com.automatethethings.xkey.storage.FakeKeyPolicyTables
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.storage.readShareable
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.KeyStore
import java.security.cert.Certificate

/**
 * #255 review r5: a key-presence probe reports present, absent or
 * unreadable, and the resolver refuses on unreadable. With the Ed25519 store
 * unreadable, a legacy general Ed25519 key's presence is unknown, so a
 * credential sharing its id is never selected in its place: no fallback, no
 * export, no use, in either namespace.
 */
class KeyPresenceUnreadableTest {

    /** Keystore aliases present. */
    private val entries = HashSet<String>()

    /** The Ed25519 preferences. */
    private val ed25519 = HashMap<String, String>()

    /** Whether the Ed25519 store can be read. */
    private var readable = true

    private lateinit var keystore: KeystoreManager

    @Before
    fun setUp() {
        mockkStatic(android.util.Log::class)
        every { android.util.Log.d(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>(), any()) } returns 0
        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } answers { firstArg<String>() in entries }
        every { platform.getCertificate(any()) } answers {
            if (firstArg<String>() in entries) mockk<Certificate>(relaxed = true) else null
        }
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns platform

        val prefs = mockk<SharedPreferences>()
        every { prefs.contains(any()) } answers { firstArg<String>() in ed25519 }
        every { prefs.getString(any(), any()) } answers { ed25519[firstArg()] ?: secondArg() }
        keystore = spyk(KeystoreManager(mockk<Context>(relaxed = true)))
        every { keystore.ed25519Prefs() } answers {
            if (!readable) throw java.security.GeneralSecurityException("master key unavailable")
            prefs
        }
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** The legacy general Ed25519 key and a credential share [GENERAL_AND_CREDENTIAL]. */
    private fun givenKeys() {
        ed25519["xkey_key_$GENERAL_AND_CREDENTIAL"] = "legacy-ed25519"
        entries += "xkey_credential_$GENERAL_AND_CREDENTIAL"
        entries += "xkey_credential_$CREDENTIAL_ONLY"
    }

    @Test
    fun aReadableStoreResolvesEachNamespace() {
        givenKeys()
        assertEquals(KeyPresence.PRESENT, keystore.ed25519Presence("xkey_key_$GENERAL_AND_CREDENTIAL"))
        assertEquals(KeyPresence.ABSENT, keystore.ed25519Presence("xkey_key_$CREDENTIAL_ONLY"))
        assertEquals(UserKeyKind.GENERAL, keystore.exportKind(GENERAL_AND_CREDENTIAL))
        assertEquals(UserKeyKind.CREDENTIAL, keystore.exportKind(CREDENTIAL_ONLY))
        assertEquals(null, keystore.soleKind(GENERAL_AND_CREDENTIAL))
        assertEquals(UserKeyKind.CREDENTIAL, keystore.soleKind(CREDENTIAL_ONLY))
    }

    @Test
    fun anUnreadableStoreIsNeverAbsent() {
        givenKeys()
        readable = false
        assertEquals(KeyPresence.UNREADABLE, keystore.ed25519Presence("xkey_key_$GENERAL_AND_CREDENTIAL"))
        assertEquals(KeyPresence.UNREADABLE, keystore.ed25519Presence("xkey_key_$CREDENTIAL_ONLY"))
        assertRefuses("hasSoftwareEd25519Key") { keystore.hasSoftwareEd25519Key("xkey_key_$CREDENTIAL_ONLY") }
    }

    /**
     * The bypass test: every resolver path of an id, in both namespaces,
     * refuses on an unreadable store; none falls through to the credential.
     */
    @Test
    fun noResolverPathFallsThroughOnAReadFailure() {
        givenKeys()
        readable = false
        for (id in listOf(GENERAL_AND_CREDENTIAL, CREDENTIAL_ONLY)) {
            val paths: List<Pair<String, () -> Any?>> = listOf(
                "resolveKey(GENERAL)" to { keystore.resolveKey(id, UserKeyKind.GENERAL) },
                "resolveKeystoreAlias(GENERAL)" to { keystore.resolveKeystoreAlias(id, UserKeyKind.GENERAL) },
                "exportKind" to { keystore.exportKind(id) },
                "soleKind" to { keystore.soleKind(id) },
                "userKeyIdInUse" to { keystore.userKeyIdInUse(id) },
                "holdsAnyKey" to { keystore.holdsAnyKey(id) },
                "holdsInternalKey" to { keystore.holdsInternalKey(id) },
                "keyExists(GENERAL)" to { keystore.keyExists(id, UserKeyKind.GENERAL) },
                "keySecurityLevel(GENERAL)" to { keystore.keySecurityLevel(id, UserKeyKind.GENERAL) },
                "generalKeySecurityLevel" to { keystore.generalKeySecurityLevel(id) },
                "getPublicKeyPEM(exportKind)" to { keystore.getPublicKeyPEM(id, keystore.exportKind(id)) }
            )
            for ((name, path) in paths) assertRefuses("$name of $id", path)
        }
    }

    /** The share read refuses in both namespaces and reads no key. */
    @Test
    fun aShareReadWithAnUnreadableStoreExportsNothing() = runTest {
        givenKeys()
        readable = false
        val tables = FakeKeyPolicyTables()
        val store = tables.store(KeyPolicyStore.KeyResolver { id, kind -> keystore.resolveKey(id, kind) })
        for (id in listOf(GENERAL_AND_CREDENTIAL, CREDENTIAL_ONLY)) {
            tables.addKey(id, SharingPolicyType.ALL_PEERS)
            var softwareRead = false
            val failure = runCatching { store.readShareable(id, keystore) { softwareRead = true; null } }.exceptionOrNull()
            assertTrue("$id shared with an unreadable store: $failure", failure is KeyPresenceUnreadableException)
            assertFalse("$id read its software key", softwareRead)
        }
        verify(exactly = 0) { keystore.getPublicKeyPEM(any(), any()) }
    }

    /**
     * The source half of the bypass test: no key-presence probe in
     * KeystoreManager swallows a read failure. A presence function (has*,
     * holds*, *Exists, *Presence, the resolver and rawAlias) holds no
     * runCatching, and each catch in one rethrows or maps to UNREADABLE.
     */
    @Test
    fun noPresenceProbeCatchesAFailureAsAbsent() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val source = File(root, "com/automatethethings/xkey/crypto/KeystoreManager.kt").readText()
        val probe = Regex("""fun (has\w*|holds\w*|\w*Exists|\w*Presence|resolveKey\w*|soleKind|exportKind|userKeyIdInUse|rawAlias)\(""")
        val probes = probe.findAll(source).map { it.groupValues[1] to body(source, it.range.first) }.toList()
        assertTrue("the probes were found: ${probes.map { it.first }}", probes.size >= 10)
        for ((name, text) in probes) {
            assertFalse("$name swallows a failure with runCatching", "runCatching" in text)
            for (handler in Regex("""catch \([^)]*\) \{([^}]*)\}""").findAll(text)) {
                val action = handler.groupValues[1]
                assertTrue(
                    "$name catches a read failure as absent: ${handler.value}",
                    "throw" in action || "KeyPresence.UNREADABLE" in action
                )
            }
        }
        assertTrue(
            "the Ed25519 probe refuses an unreadable store",
            "throw KeyPresenceUnreadableException" in probes.single { it.first == "hasSoftwareEd25519Key" }.second
        )
    }

    /** The text of the function starting at [start]: to its closing brace, or its expression's end. */
    private fun body(source: String, start: Int): String {
        val next = source.indexOf("\n    fun ", start + 1).let { if (it < 0) source.length else it }
        val nextInternal = source.indexOf("\n    internal fun ", start + 1).let { if (it < 0) source.length else it }
        val nextPrivate = source.indexOf("\n    private fun ", start + 1).let { if (it < 0) source.length else it }
        return source.substring(start, minOf(next, nextInternal, nextPrivate))
    }

    private fun assertRefuses(name: String, path: () -> Any?) {
        val failure = runCatching(path).exceptionOrNull()
        assertTrue("$name did not refuse an unreadable store: ${failure ?: "returned"}", failure is KeyPresenceUnreadableException)
    }

    private companion object {
        const val GENERAL_AND_CREDENTIAL = "shared-id"
        const val CREDENTIAL_ONLY = "credential-only"
    }
}
