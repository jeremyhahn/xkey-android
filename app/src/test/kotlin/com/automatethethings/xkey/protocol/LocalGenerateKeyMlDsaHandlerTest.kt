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

package com.automatethethings.xkey.protocol

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import androidx.biometric.BiometricManager
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.crypto.BiometricRequiredException
import com.automatethethings.xkey.crypto.CryptoObjectSigner
import com.automatethethings.xkey.crypto.KeySecurityLevel
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.MlDsaParameterSet
import com.automatethethings.xkey.crypto.PqcBacking
import com.automatethethings.xkey.crypto.PqcHardware
import com.automatethethings.xkey.crypto.PqcHardwareBackend
import com.automatethethings.xkey.settings.DeviceLookup
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import java.security.KeyStore
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * ML-DSA keys through the real [RequestHandler]: the backing a request gets,
 * the refusals (hardware the device lacks, an exportable key, an unknown
 * backing), signing under the key's own set, the export formats an ML-DSA
 * key has, delete, and `hardwareAlgorithms` in `local.getCapabilities`.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class LocalGenerateKeyMlDsaHandlerTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var handler: RequestHandler
    private lateinit var keystore: KeystoreManager
    private lateinit var keyDao: KeyDao
    private lateinit var handlerContext: Context
    private lateinit var pairedDevices: PairedDeviceRepository
    private val savedBackend = PqcHardware.backend

    /** The backing of every generateMlDsaKey call, in order. */
    private val backings = mutableListOf<PqcBacking>()
    private val stored = slot<KeyEntity>()
    private val spki = ByteArray(MlDsaParameterSet.ML_DSA_65.publicKeyBytes + 22) { (it % 251).toByte() }

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
        Dispatchers.setMain(UnconfinedTestDispatcher())
        PqcHardware.backend = null

        keyDao = mockk(relaxed = true)
        coEvery { keyDao.insert(capture(stored)) } returns 1L
        coEvery { keyDao.getByKeyId(any()) } returns null
        coEvery { keyDao.getByKeyId("pq") } returns KeyEntity(
            keyId = "pq", keyType = "signing", algorithm = "ML-DSA-65", label = "pq",
            keySizeBits = MlDsaParameterSet.ML_DSA_65.publicKeyBytes * 8, source = "local"
        )
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)

        keystore = mockk(relaxed = true)
        coEvery { keystore.generateMlDsaKey(any(), any(), any(), any(), any()) } answers {
            backings += thirdArg<PqcBacking>()
            spki
        }
        every { keystore.generalKeySecurityLevel(any()) } answers {
            if (backings.lastOrNull() == PqcBacking.HARDWARE) KeySecurityLevel.TEE else KeySecurityLevel.SOFTWARE
        }
        every { keystore.generalKeyExists("pq") } returns true
        every { keystore.publicKeyDERAt(KeystoreManager.generalKeyAlias("pq")) } returns spki
        every { keystore.getPublicKeyDER("pq") } returns spki
        coEvery { keystore.signApprovedMlDsa(any(), any(), any(), any()) } returns
            ByteArray(MlDsaParameterSet.ML_DSA_65.signatureBytes) { 9 }

        val context = mockk<Context>(relaxed = true)
        handlerContext = context
        every { context.filesDir } returns tmp.root
        every { context.applicationContext } returns context
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)
        mockkStatic(BiometricManager::class)
        every { BiometricManager.from(any()) } returns mockk(relaxed = true)
        pairedDevices = mockk<PairedDeviceRepository>()
        every { pairedDevices.lookupDevice(any()) } returns DeviceLookup.Paired(device())

        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices,
            pinManager = mockk(relaxed = true)
        )
        handler.setConnectedDevicePublicKeyHex(PEER)
    }

    @After
    fun tearDown() {
        PqcHardware.backend = savedBackend
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Test
    fun `with no hardware an ML-DSA key is made in software and stored under its set`() = runTest {
        val response = generate("""{"keyId":"new","algorithm":"ML-DSA-65","requireUserVerification":false}""")

        val result = response.optJSONObject("result")
        assertTrue("ML-DSA-65 must succeed, got $response", result != null)
        assertEquals(listOf(PqcBacking.SOFTWARE), backings)
        assertEquals(MlDsaParameterSet.ML_DSA_65.publicKeyBytes * 8, result!!.getInt("keySizeBits"))
        assertEquals("ML-DSA-65", stored.captured.algorithm)
        assertEquals(MlDsaParameterSet.ML_DSA_65.publicKeyBytes * 8, stored.captured.keySizeBits)
        coVerify(exactly = 0) { keystore.generateKeyForAlgorithm(any(), any(), any(), any(), any()) }
    }

    @Test
    fun `a request cancelled while its ML-DSA key is made leaves both the key and its row or neither`() = runTest {
        val material = java.util.Collections.synchronizedSet(mutableSetOf<String>())
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        coEvery { keystore.generateMlDsaKey("c", any(), any(), any(), any()) } answers {
            entered.countDown()
            release.await(10, TimeUnit.SECONDS)
            material += "c"
            spki
        }
        every { keystore.deleteGeneralKey("c") } answers { material.remove("c") }

        val request = CoroutineScope(Dispatchers.Default).launch {
            generate("""{"keyId":"c","algorithm":"ML-DSA-65","requireUserVerification":false}""")
        }
        assertTrue("generation never started", entered.await(10, TimeUnit.SECONDS))
        request.cancel()
        release.countDown()
        request.join()

        val rowStored = stored.isCaptured && stored.captured.keyId == "c"
        assertEquals("key material $material, row stored $rowStored", "c" in material, rowStored)
    }

    @Test
    fun `an ML-DSA key whose row cannot be stored is removed and a retry succeeds`() = runTest {
        val material = mutableSetOf<String>()
        coEvery { keystore.generateMlDsaKey("f", any(), any(), any(), any()) } answers {
            material += "f"
            spki
        }
        every { keystore.deleteGeneralKey("f") } answers { material.remove("f") }
        every { keystore.generalKeyExists("f") } answers { "f" in material }
        var inserts = 0
        coEvery { keyDao.insert(match { it.keyId == "f" }) } answers {
            if (inserts++ == 0) throw IllegalStateException("database is full") else 1L
        }
        val params = """{"keyId":"f","algorithm":"ML-DSA-65","requireUserVerification":false}"""

        val first = generate(params)
        assertTrue("the first request must fail, got $first", first.has("error"))
        assertFalse("the unrecorded key must be removed", "f" in material)

        val retry = generate(params)
        assertFalse(retry.toString(), retry.has("error"))
        assertTrue("f" in material)
        assertEquals(2, inserts)
    }

    @Test
    fun `every ML-DSA generation in the app runs inside the cancellation-safe unit that stores its row`() {
        val root = java.io.File("src/main/kotlin/com/automatethethings/xkey")
        val generateCall = Regex("""(?<!fun )\bgenerateMlDsaKey\(""")
        val callers = root.walk()
            .filter { it.extension == "kt" && generateCall.containsMatchIn(it.readText()) }
            .map { it.relativeTo(root).path }.toList()
        assertEquals("generateMlDsaKey has one caller, the commit unit", listOf("crypto/MlDsaKeyCommit.kt"), callers)

        val unitSource = java.io.File(root, "crypto/MlDsaKeyCommit.kt").readText()
        val calls = generateCall.findAll(unitSource).map { it.range.first }.toList()
        assertEquals("one generateMlDsaKey call", 1, calls.size)
        val nonCancellable = unitSource.indexOf("withContext(NonCancellable)")
        assertTrue("the generation is outside the NonCancellable unit", nonCancellable in 0 until calls[0])
        assertTrue("the row commit is not in the same unit", unitSource.indexOf("commit(", calls[0]) > calls[0])
        assertTrue("uncommitted material is not removed", unitSource.indexOf("deleteGeneralKey(", calls[0]) > calls[0])

        val unitCall = Regex("""(?<!fun <T> KeystoreManager)\.generateMlDsaKeyAndCommit\(""")
        val users = root.walk()
            .filter { it.extension == "kt" && unitCall.containsMatchIn(it.readText()) }
            .map { it.relativeTo(root).path }.sorted().toList()
        assertEquals(listOf("protocol/Handler.kt", "ui/KeyManagementActivity.kt"), users)
        for (path in users) {
            val source = java.io.File(root, path).readText()
            val uses = unitCall.findAll(source).map { it.range.first }.toList()
            assertEquals("$path: one generateMlDsaKeyAndCommit call", 1, uses.size)
            val insert = source.indexOf("keyDao.insert(", uses[0])
            val nextFunction = source.indexOf("\n/**", uses[0]).let { if (it < 0) source.length else it }
                .coerceAtMost(source.indexOf("\n    /**", uses[0]).let { if (it < 0) source.length else it })
            assertTrue("$path: the row is not stored in the unit", insert in uses[0]..nextFunction)
        }

        val handler = java.io.File(root, "protocol/Handler.kt").readText()
        val use = unitCall.find(handler)!!.range.first
        val unit = handler.lastIndexOf("persistAudited(write = {", use)
        val owner = handler.lastIndexOf("private suspend fun createMlDsaKey(", use)
        assertTrue("the call is not in createMlDsaKey", owner >= 0)
        assertTrue("the call is outside persistAudited", unit > owner)
    }

    @Test
    fun `a set the device makes in hardware defaults to hardware`() = runTest {
        PqcHardware.backend = backend(MlDsaParameterSet.ML_DSA_65)

        val response = generate("""{"keyId":"hw","algorithm":"ML-DSA-65","requireUserVerification":false}""")

        assertFalse(response.toString(), response.has("error"))
        assertEquals(listOf(PqcBacking.HARDWARE), backings)
    }

    @Test
    fun `an explicit software backing is honoured even when hardware exists`() = runTest {
        PqcHardware.backend = backend(MlDsaParameterSet.ML_DSA_65)

        val response = generate(
            """{"keyId":"sw","algorithm":"ML-DSA-65","keyBacking":"software","requireUserVerification":false}"""
        )

        assertFalse(response.toString(), response.has("error"))
        assertEquals(listOf(PqcBacking.SOFTWARE), backings)
    }

    @Test
    fun `hardware the device does not make is FEATURE_UNAVAILABLE and makes nothing`() = runTest {
        assertError(
            ErrorCodes.FEATURE_UNAVAILABLE,
            generate("""{"keyId":"x","algorithm":"ML-DSA-87","keyBacking":"hardware","requireUserVerification":false}""")
        )
        PqcHardware.backend = backend(MlDsaParameterSet.ML_DSA_44)
        assertError(
            ErrorCodes.FEATURE_UNAVAILABLE,
            generate("""{"keyId":"x","algorithm":"ML-DSA-87","keyBacking":"hardware","requireUserVerification":false}""")
        )
        assertEquals(emptyList<PqcBacking>(), backings)
        coVerify(exactly = 0) { keyDao.insert(any()) }
    }

    @Test
    fun `an exportable ML-DSA key is INVALID_PARAMS`() = runTest {
        assertError(
            ErrorCodes.INVALID_PARAMS,
            generate("""{"keyId":"x","algorithm":"ML-DSA-44","exportable":true,"requireUserVerification":false}""")
        )
        assertEquals(emptyList<PqcBacking>(), backings)
    }

    @Test
    fun `an unknown backing is INVALID_PARAMS`() = runTest {
        assertError(
            ErrorCodes.INVALID_PARAMS,
            generate("""{"keyId":"x","algorithm":"ML-DSA-44","keyBacking":"cloud","requireUserVerification":false}""")
        )
        assertEquals(emptyList<PqcBacking>(), backings)
    }

    @Test
    fun `sign uses the key's own set`() = runTest {
        val data = Base64.getEncoder().encodeToString("to sign".toByteArray())

        val response = call(MethodNames.LOCAL_SIGN, """{"keyId":"pq","data":"$data","userVerificationRequired":false}""")

        val result = response.optJSONObject("result")
        assertTrue("sign must succeed, got $response", result != null)
        assertEquals("ML-DSA-65", result!!.getString("algorithm"))
        assertEquals(
            MlDsaParameterSet.ML_DSA_65.signatureBytes,
            Base64.getDecoder().decode(result.getString("signature")).size
        )
        coVerify {
            keystore.signApprovedMlDsa(KeystoreManager.generalKeyAlias("pq"), spki, any(), MlDsaParameterSet.ML_DSA_65)
        }
        coVerify(exactly = 0) { keystore.signApproved(any(), any(), any(), any()) }
    }

    @Test
    fun `sign naming another set is INVALID_ALGORITHM`() = runTest {
        val data = Base64.getEncoder().encodeToString("to sign".toByteArray())

        val response = call(
            MethodNames.LOCAL_SIGN,
            """{"keyId":"pq","data":"$data","algorithm":"ML-DSA-44","userVerificationRequired":false}"""
        )

        assertError(ErrorCodes.INVALID_ALGORITHM, response)
        coVerify(exactly = 0) { keystore.signApprovedMlDsa(any(), any(), any(), any()) }
    }

    @Test
    fun `sign of a per-operation hardware key binds the Signature to the prompt, with no generic prompt`() = runTest {
        val alias = KeystoreManager.generalKeyAlias("pq")
        val launcher = mockk<BiometricActivityLauncher>(relaxed = true)
        val boundSignature = ByteArray(MlDsaParameterSet.ML_DSA_65.signatureBytes) { 5 }
        coEvery {
            launcher.requestCryptoSignature(any(), any(), any(), any(), any(), alias, "ML-DSA-65", any())
        } returns boundSignature
        every { keystore.isPerOperationKey(alias) } returns true
        coEvery { keystore.signApprovedMlDsa(alias, spki, any(), MlDsaParameterSet.ML_DSA_65, any(), any()) } coAnswers {
            val signer = arg<CryptoObjectSigner?>(5) ?: throw BiometricRequiredException()
            signer.sign(alias, "ML-DSA-65", thirdArg())
        }
        handler = RequestHandler(
            context = handlerContext,
            keystoreManager = keystore,
            biometricLauncher = launcher,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices,
            pinManager = mockk(relaxed = true)
        )
        handler.setConnectedDevicePublicKeyHex(PEER)
        val data = Base64.getEncoder().encodeToString("to sign".toByteArray())

        val response = call(MethodNames.LOCAL_SIGN, """{"keyId":"pq","data":"$data","userVerificationRequired":true}""")

        val result = response.optJSONObject("result")
        assertTrue("sign must succeed, got $response", result != null)
        assertArrayEquals(boundSignature, Base64.getDecoder().decode(result!!.getString("signature")))
        coVerify(exactly = 0) { launcher.requestAuthentication(any(), any(), any(), any(), any()) }
        coVerify(exactly = 1) {
            launcher.requestCryptoSignature("pq", "to sign".toByteArray(), any(), any(), any(), alias, "ML-DSA-65", any())
        }
    }

    @Test
    fun `an ML-DSA public key exports as DER and PEM, never SSH or COSE`() = runTest {
        for (format in listOf(ExportFormats.DER, ExportFormats.PEM)) {
            val response = call(MethodNames.LOCAL_GET_PUBLIC_KEY, """{"keyId":"pq","format":"$format"}""")
            assertFalse("$format: $response", response.has("error"))
        }
        for (format in listOf(ExportFormats.SSH, ExportFormats.COSE)) {
            assertError(
                ErrorCodes.UNSUPPORTED_FORMAT,
                call(MethodNames.LOCAL_GET_PUBLIC_KEY, """{"keyId":"pq","format":"$format"}""")
            )
        }
    }

    @Test
    fun `delete removes a software ML-DSA key through the keystore choke point`() = runTest {
        every { keystore.pqcSoftwareKeyExists("pq") } returns true

        val response = call(MethodNames.LOCAL_DELETE_KEY, """{"keyId":"pq"}""")

        assertFalse(response.toString(), response.has("error"))
        verify { keystore.deleteGeneralKey("pq") }
    }

    @Test
    fun `capabilities list ML-DSA and only the hardware sets the backend makes`() = runTest {
        PqcHardware.backend = backend(MlDsaParameterSet.ML_DSA_44)

        val result = call(MethodNames.LOCAL_GET_CAPABILITIES, "{}").getJSONObject("result")

        val algorithms = result.getJSONArray("algorithms").let { a -> (0 until a.length()).map { a.getString(it) } }
        assertTrue(algorithms.containsAll(listOf("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")))
        val hardware = result.getJSONArray("hardwareAlgorithms")
        assertEquals(1, hardware.length())
        assertEquals("ML-DSA-44", hardware.getString(0))
    }

    @Test
    fun `each set is made by name and by COSE id and returns its SPKI and a software level`() = runTest {
        val expectedDer = Base64.getEncoder().encodeToString(spki)
        for (set in MlDsaParameterSet.entries) {
            for (algorithm in listOf("\"${set.wireName}\"", set.coseAlgorithm.toString())) {
                backings.clear()
                val response = generate(
                    """{"keyId":"k","algorithm":$algorithm,"keyBacking":"software","requireUserVerification":false}"""
                )

                val result = response.optJSONObject("result")
                assertTrue("$algorithm must succeed, got $response", result != null)
                assertEquals(algorithm, listOf(PqcBacking.SOFTWARE), backings)
                assertEquals(algorithm, set.wireName, result!!.getString("algorithm"))
                assertEquals(algorithm, expectedDer, result.getString("publicKeyDer"))
                assertEquals(algorithm, "software", result.getString("securityLevel"))
                assertEquals(algorithm, set.wireName, stored.captured.algorithm)
            }
        }
    }

    @Test
    fun `a keyBacking that is not a string is INVALID_PARAMS`() = runTest {
        for (raw in listOf("1", "true", "{}", "[\"software\"]")) {
            assertError(
                ErrorCodes.INVALID_PARAMS,
                generate("""{"keyId":"x","algorithm":"ML-DSA-65","keyBacking":$raw,"requireUserVerification":false}""")
            )
        }
        assertEquals(emptyList<PqcBacking>(), backings)
    }

    @Test
    fun `a keyBacking on a key that is not ML-DSA is INVALID_PARAMS`() = runTest {
        for (algorithm in listOf("ES256", "RS256", "AES-256")) {
            for (backing in listOf("software", "hardware")) {
                assertError(
                    ErrorCodes.INVALID_PARAMS,
                    generate(
                        """{"keyId":"x","algorithm":"$algorithm","keyBacking":"$backing","requireUserVerification":false}"""
                    )
                )
            }
        }
        coVerify(exactly = 0) { keystore.generateKeyForAlgorithm(any(), any(), any(), any(), any()) }
        coVerify(exactly = 0) { keyDao.insert(any()) }
    }

    @Test
    fun `an ML-DSA FIDO2 credential is INVALID_ALGORITHM`() = runTest {
        for (set in MlDsaParameterSet.entries) {
            assertError(
                ErrorCodes.INVALID_ALGORITHM,
                generate(
                    """{"keyId":"x","algorithm":"${set.wireName}","keyType":"fido2","rpId":"example.com","requireUserVerification":false}"""
                )
            )
        }
        assertEquals(emptyList<PqcBacking>(), backings)
        coVerify(exactly = 0) { keyDao.insert(any()) }
    }

    private fun assertError(code: Int, response: JSONObject) {
        assertTrue("expected error $code, got $response", response.has("error"))
        assertEquals(response.toString(), code, response.getJSONObject("error").getInt("code"))
    }

    private suspend fun generate(params: String) = call(MethodNames.LOCAL_GENERATE_KEY, params)

    private suspend fun call(method: String, params: String): JSONObject {
        val request = """{"jsonrpc":"2.0","id":1,"method":"$method","params":$params}"""
        return withContext(RequestHandler.servedConnection(binding, PEER, "test:connection")) {
            JSONObject(String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
        }
    }

    private fun device(): PairedDeviceData = mockk(relaxed = true) {
        every { deviceName } returns "Desktop"
        every { requireAttestationForKeyUse } returns false
    }

    private fun backend(vararg sets: MlDsaParameterSet) = object : PqcHardwareBackend {
        override fun supportedParameterSets() = sets.toSet()
        override fun generate(
            alias: String,
            set: MlDsaParameterSet,
            authDurationSeconds: Int,
            preferStrongBox: Boolean
        ): ByteArray = throw UnsupportedOperationException("the keystore mock makes the key")
        override fun jcaSignatureAlgorithm(set: MlDsaParameterSet) = set.wireName
    }

    private companion object {
        const val PEER = "aa01"
        val binding = SessionBindingProvider {
            SessionBinding(ByteArray(32) { 3 }, ByteArray(32) { 4 }, ByteArray(0))
        }
    }
}
