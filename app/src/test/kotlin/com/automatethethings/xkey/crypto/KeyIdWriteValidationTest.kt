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
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.MessageDigest

/**
 * #255 verify r6: the record reader rejected an empty key id, but the
 * writer took one, so a peer's local.generateKey with keyId "" wrote a
 * record whose metadata names no id; the reader could not attribute it and
 * read every id with no record of its own as unreadable. A write now takes
 * only an id the reader accepts ([SoftwareKeyStore.isValidKeyId]), and a
 * record already written under the digest of the id it names is that id's,
 * whatever that id is, never an unknown id's.
 */
class KeyIdWriteValidationTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var filesDir: File

    @Before
    fun setUp() {
        mockkStatic(android.util.Log::class)
        every { android.util.Log.d(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>(), any()) } returns 0
        filesDir = tmp.newFolder()
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private val dir get() = File(filesDir, "software_keys")

    private fun store(): SoftwareKeyStore {
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers { firstArg<ByteArray>().copyOf() }
        every { cipher.decrypt(any()) } answers { firstArg<ByteArray>().copyOf() }
        return SoftwareKeyStore(context, cipher)
    }

    private fun key(id: String) =
        SoftwareKey(id, "AES", "symmetric", 256, exportable = true, shareable = true, material = ByteArray(32) { 5 })

    @Test
    fun aWriteOfAnIdTheReaderRejectsIsRefusedWithNoFileWritten() {
        val store = store()
        assertFalse(SoftwareKeyStore.isValidKeyId(""))
        assertTrue(SoftwareKeyStore.isValidKeyId(ID))
        val failure = runCatching { store.put(key("")) }.exceptionOrNull()
        assertTrue("an empty key id was written: $failure", failure is IllegalArgumentException)
        assertEquals("files written for an empty id", emptyList<String>(), dir.list()?.toList().orEmpty())
        assertEquals(KeyPresence.ABSENT, store.presence(ID))
    }

    /** What a build that took the empty id left: its record under the digest of "". */
    @Test
    fun aPlantedEmptyIdRecordLeavesUnrelatedIdsAsTheyWere() {
        store().put(key(ID))
        File(dir, "${digest("")}.key").writeBytes(ByteArray(32) { 9 })
        File(dir, "${digest("")}.meta").writeText("""{"keyId":"","algorithm":"AES","keyType":"symmetric","keySize":256,"exportable":true}""")

        val store = store()
        assertEquals("a held id", KeyPresence.PRESENT, store.presence(ID))
        assertEquals(ID, store.get(ID)?.keyId)
        assertEquals("an unrelated id with no record", KeyPresence.ABSENT, store.presence(OTHER))
        assertNull(store.get(OTHER))
    }

    /**
     * The bypass guard (ruling 554): every record write is the store's put,
     * which checks the id first, and the reader and the writer share the
     * one validator; local.generateKey checks its parsed id with it before
     * any key is made.
     */
    @Test
    fun noWritePathTakesAnIdTheReaderRejects() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val source = File(root, "com/automatethethings/xkey/crypto/SoftwareKeyStore.kt").readText()
        // The one file write is the writeFile parameter's default; every
        // record write goes through writeFile.
        assertEquals("record writes in the store", 1, Regex("""\.write(Bytes|Text)\(""").findAll(source).count())
        assertEquals("writeFile calls in the store", 2, Regex("""\bwriteFile\(""").findAll(source).count())
        val put = source.substringAfter("fun put(key: SoftwareKey) {").substringBefore("\n    }\n")
        assertTrue("put writes before checking its id", put.trimStart().startsWith("requireValidKeyId(key.keyId)"))
        assertEquals("both writes are put's", 2, Regex("""\bwriteFile\(""").findAll(put).count())
        assertTrue("the reader does not use the writer's validator", "?.takeIf(::isValidKeyId)" in source)
        val handler = File(root, "com/automatethethings/xkey/protocol/Handler.kt").readText()
        val generate = handler.substringAfter("private suspend fun handleLocalGenerateKey(").substringBefore("private ")
        val parse = generate.indexOf("LocalGenerateKeyParams.fromJson(params)")
        val check = generate.indexOf("SoftwareKeyStore.isValidKeyId(genParams.keyId)")
        assertTrue("local.generateKey does not check its id right after parsing", parse in 0 until check)
        assertTrue("the id is used before its check", "genParams.keyId" !in generate.substring(parse, check))
    }

    private fun digest(id: String): String =
        MessageDigest.getInstance("SHA-256").digest(id.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    private companion object {
        const val ID = "held-key"
        const val OTHER = "unrelated-key"
    }
}
