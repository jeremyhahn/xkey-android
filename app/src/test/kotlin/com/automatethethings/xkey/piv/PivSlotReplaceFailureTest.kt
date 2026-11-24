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

package com.automatethethings.xkey.piv

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import com.automatethethings.xkey.crypto.MlDsaParameterSet
import com.automatethethings.xkey.crypto.PqcBacking
import com.automatethethings.xkey.crypto.PqcHardware
import com.automatethethings.xkey.crypto.PqcHardwareBackend
import com.automatethethings.xkey.crypto.PqcSoftwareKeyStore
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import java.io.File
import java.io.IOException
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * A slot key replacement that fails leaves the slot whole: either the old
 * key, its row and its certificate, or no key and no row at all. It never
 * leaves a row (with the old certificate) describing a key the slot no
 * longer holds. Covers a failed software ML-DSA write, a failed hardware
 * ML-DSA generate and a failed classical generate.
 */
class PivSlotReplaceFailureTest {

    private val slot = PivSlot.AUTHENTICATION
    private val alias = slot.keystoreAlias
    private val oldKey = PivTestCertificates.ecKeyPair()
    private val oldRow = PivTestCertificates.slotRow(oldKey.public.encoded, PivTestCertificates.selfSigned(oldKey))
    private lateinit var keystore: FakePivKeystore
    private lateinit var pivSlotDao: PivSlotDao
    private val savedBackend = PqcHardware.backend

    /** The slot's row as the DAO holds it. */
    private var row: PivSlotEntity? = null

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logKeyCreated(any(), any(), any(), any()) } returns Unit
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } returns Unit
        PqcSoftwareKeyStore.clearSharedForTest()

        keystore = FakePivKeystore(oldKey).also { it.install() }
        row = oldRow
        pivSlotDao = mockk(relaxed = true)
        coEvery { pivSlotDao.getBySlotId(slot.hexId) } answers { row }
        coEvery { pivSlotDao.upsert(any()) } answers { row = firstArg(); 1L }
        coEvery { pivSlotDao.deleteBySlotId(slot.hexId) } answers { row = null; 1 }
    }

    @After
    fun tearDown() {
        PqcHardware.backend = savedBackend
        PqcSoftwareKeyStore.clearSharedForTest()
        unmockkAll()
    }

    @Test
    fun `a failed software ML-DSA write leaves the old key, row and certificate, or none of them`() = runTest {
        keystore.live = null
        val store = spyk(softwareStore())
        val oldSpki = store.generate(alias, MlDsaParameterSet.ML_DSA_44)
        val softwareRow = oldRow.copy(algorithm = PivAlgorithm.ML_DSA_44.name, publicKeyDer = oldSpki)
        row = softwareRow
        every { store.generate(alias, MlDsaParameterSet.ML_DSA_87, any()) } throws IOException("Cannot store ML-DSA key")

        val error = runCatching {
            PivKeyManager(pivSlotDao, pqcStore = store).generateKey(slot, PivAlgorithm.ML_DSA_87, PqcBacking.SOFTWARE)
        }.exceptionOrNull()

        assertTrue("$error", error is IOException)
        assertOldOrNone(keyPresent = store.contains(alias), old = softwareRow)
    }

    @Test
    fun `a failed hardware ML-DSA generate leaves the old key, row and certificate, or none of them`() = runTest {
        PqcHardware.backend = object : PqcHardwareBackend {
            override fun supportedParameterSets() = MlDsaParameterSet.entries.toSet()
            override fun generate(alias: String, set: MlDsaParameterSet, authDurationSeconds: Int, preferStrongBox: Boolean) =
                throw IllegalStateException("StrongBox refused the key")
            override fun jcaSignatureAlgorithm(set: MlDsaParameterSet) = "ML-DSA"
        }

        val error = runCatching {
            PivKeyManager(pivSlotDao).generateKey(slot, PivAlgorithm.ML_DSA_65, PqcBacking.HARDWARE)
        }.exceptionOrNull()

        assertTrue("$error", error is IllegalStateException)
        assertOldOrNone(keyPresent = keystore.live != null, old = oldRow)
    }

    @Test
    fun `a failed classical generate leaves the old key, row and certificate, or none of them`() = runTest {
        val generate: (String, PivAlgorithm) -> java.security.KeyPair = { _, _ ->
            keystore.live = null
            throw IllegalStateException("Keystore refused the key")
        }

        val error = runCatching {
            PivKeyManager(pivSlotDao, generateKeyPair = generate).generateKey(slot, PivAlgorithm.ES256, PqcBacking.HARDWARE)
        }.exceptionOrNull()

        assertTrue("$error", error is IllegalStateException)
        assertOldOrNone(keyPresent = keystore.live != null, old = oldRow)
    }

    @Test
    fun `an old software ML-DSA record that cannot be removed keeps its row and certificate when replaced by ES256`() = runTest {
        val (store, softwareRow) = undeletableSoftwareSlot()

        val error = runCatching {
            PivKeyManager(pivSlotDao, pqcStore = store).generateKey(slot, PivAlgorithm.ES256, PqcBacking.HARDWARE)
        }.exceptionOrNull()

        assertTrue("$error", error is IOException)
        assertTrue("the old key still signs", store.contains(alias))
        assertEquals(softwareRow, row)
    }

    @Test
    fun `an old software ML-DSA record that cannot be removed keeps its row and certificate when replaced by hardware ML-DSA`() = runTest {
        val (store, softwareRow) = undeletableSoftwareSlot()
        PqcHardware.backend = object : PqcHardwareBackend {
            override fun supportedParameterSets() = MlDsaParameterSet.entries.toSet()
            override fun generate(alias: String, set: MlDsaParameterSet, authDurationSeconds: Int, preferStrongBox: Boolean) =
                throw AssertionError("the old key was not removed")
            override fun jcaSignatureAlgorithm(set: MlDsaParameterSet) = "ML-DSA"
        }

        val error = runCatching {
            PivKeyManager(pivSlotDao, pqcStore = store).generateKey(slot, PivAlgorithm.ML_DSA_65, PqcBacking.HARDWARE)
        }.exceptionOrNull()

        assertTrue("$error", error is IOException)
        assertTrue("the old key still signs", store.contains(alias))
        assertEquals(softwareRow, row)
    }

    /** The slot holding a software ML-DSA key, with its row, whose record cannot be removed. */
    private fun undeletableSoftwareSlot(): Pair<PqcSoftwareKeyStore, PivSlotEntity> {
        keystore.live = null
        val store = softwareStore()
        val oldSpki = store.generate(alias, MlDsaParameterSet.ML_DSA_44)
        val softwareRow = oldRow.copy(algorithm = PivAlgorithm.ML_DSA_44.name, publicKeyDer = oldSpki)
        row = softwareRow
        store.removeFile = { false }
        return store to softwareRow
    }

    @Test
    fun `every slot key generate runs inside replaceSlotKey, whose failure path empties the slot`() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val text = File(root, "com/automatethethings/xkey/piv/PivKeyManager.kt").readText()

        // Key material is made or removed for a generate only in slotKeyMaker's lambdas.
        assertEquals(
            setOf("slotKeyMaker"),
            enclosingFunctions(text, Regex("""generateKeyPair\(alias|\.generate\(alias""")).toSet()
        )
        assertEquals(setOf("generateKeyLocked"), enclosingFunctions(text, Regex("""(?<!fun )\bslotKeyMaker\(""")).toSet())

        val locked = body(text, "generateKeyLocked")
        val guard = locked.indexOf("replaceSlotKey(slot)")
        assertTrue("generateKeyLocked replaces through replaceSlotKey", guard >= 0)
        assertTrue("the key is made inside replaceSlotKey", guard < locked.indexOf("makeKey()"))
        assertTrue("the row is written inside replaceSlotKey", guard < locked.indexOf("pivSlotDao.upsert("))

        val replace = body(text, "replaceSlotKey")
        assertTrue("every failure, cancellation included, is caught", replace.contains("catch (e: Throwable)"))
        assertTrue("the failure path empties the slot", replace.contains("discardUnrecordedKey(slot)"))
        assertTrue("the failure path cannot be cancelled", replace.contains("withContext(NonCancellable)"))

        val discard = body(text, "discardUnrecordedKey")
        val keep = discard.indexOf("live.contentEquals(row.publicKeyDer)")
        assertTrue("a key that is still the row's keeps its row", keep >= 0)
        assertTrue("the keep check comes before any removal", keep < discard.indexOf("deleteBySlotId("))
        assertTrue("the keep check comes before any key removal", keep < discard.indexOf("deleteEntry("))
    }

    /** The name of the function each [call] match sits in. */
    private fun enclosingFunctions(text: String, call: Regex): List<String> {
        val fn = Regex("""\bfun\s+(?:<[^>]*>\s*)?([A-Za-z0-9_]+)\s*\(""")
        return call.findAll(text).map { match ->
            fn.findAll(text.substring(0, match.range.first)).lastOrNull()?.groupValues?.get(1) ?: "<top>"
        }.toList()
    }

    private fun body(text: String, name: String): String {
        val start = Regex("""\bfun\s+(?:<[^>]*>\s*)?$name\(""").find(text)?.range?.first ?: return ""
        return text.substring(start, text.indexOf("\n    }\n", start))
    }

    private fun assertOldOrNone(keyPresent: Boolean, old: PivSlotEntity) {
        val kept = keyPresent && row == old
        val emptied = !keyPresent && row == null
        assertTrue("slot left key=$keyPresent row=${row?.algorithm} cert=${row?.certificateDer != null}", kept || emptied)
    }

    /** A software ML-DSA store over a temporary directory and a stand-in seal. */
    private fun softwareStore(): PqcSoftwareKeyStore {
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers { firstArg<ByteArray>().reversedArray() }
        every { cipher.decrypt(any()) } answers { firstArg<ByteArray>().reversedArray() }
        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns java.nio.file.Files.createTempDirectory("piv-replace").toFile()
        return PqcSoftwareKeyStore(context, cipher)
    }
}
