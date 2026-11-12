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
package com.automatethethings.xkey.ui

import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.RemoteAttestKeyResult
import com.automatethethings.xkey.protocol.RemoteBackendInfo
import com.automatethethings.xkey.protocol.RemoteGetKeyInfoResult
import com.automatethethings.xkey.protocol.RemoteGetPublicKeyResult
import com.automatethethings.xkey.protocol.RemoteKeyInfo
import com.automatethethings.xkey.protocol.RemoteSignResult
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.RemoteKeyClient
import com.automatethethings.xkey.remote.ScriptedMessageSender
import com.automatethethings.xkey.remote.stubAndroidLog
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.util.Base64

/** JVM tests for [DesktopKeysController], the view-free half of the desktop keys screen. */
class DesktopKeysControllerTest {

    private val tpm = RemoteBackendInfo(
        name = "tpm2", type = "tpm2", hardwareBacked = true, signing = true, decryption = true,
        symmetricCrypto = false, keyAgreement = true, attestation = true
    )
    private val soft = tpm.copy(name = "software", type = "software", hardwareBacked = false, attestation = false)
    private val key = RemoteKeyInfo("k1", "tpm2", "ecdsa-p256", 256, "Signing key", 1_700_000_000L)
    private val info = RemoteGetKeyInfoResult("k1", "tpm2", "ecdsa-p256", 256, "Signing key", 1_700_000_000L, true, false)
    private val publicKey = RemoteGetPublicKeyResult("MFkwEwYHKoZIzj0CAQ==", "der", "ecdsa-p256")

    /** A desktop that answers from fields and records each call. */
    private inner class FakeSource : DesktopKeysSource {
        val calls = mutableListOf<String>()
        var failure: Exception? = null
        var valid = true
        var attestation: (String) -> RemoteAttestKeyResult = { nonce ->
            RemoteAttestKeyResult("tpm2", listOf("A", "B"), Base64.getEncoder().encodeToString(ByteArray(5)), nonce)
        }
        var lastVerify: List<String> = emptyList()
        /** Runs when sign is called, before it answers. */
        var onSign: () -> Unit = {}

        private fun call(name: String) {
            calls += name
            failure?.let { throw it }
        }

        override suspend fun listBackends(): List<RemoteBackendInfo> { call("listBackends"); return listOf(tpm, soft) }
        override suspend fun listKeys(backend: String): List<RemoteKeyInfo> { call("listKeys:$backend"); return listOf(key) }
        override suspend fun getKeyInfo(backend: String, keyId: String): RemoteGetKeyInfoResult {
            call("getKeyInfo:$backend:$keyId"); return info
        }
        override suspend fun getPublicKey(backend: String, keyId: String): RemoteGetPublicKeyResult {
            call("getPublicKey:$backend:$keyId"); return publicKey
        }
        override suspend fun sign(backend: String, keyId: String, data: String): RemoteSignResult {
            call("sign:$backend:$keyId"); onSign(); return RemoteSignResult("c2ln", "ecdsa-p256-sha256")
        }
        override suspend fun verify(
            backend: String, keyId: String, data: String, signature: String, algorithm: String
        ): Boolean {
            call("verify:$backend:$keyId"); lastVerify = listOf(data, signature, algorithm); return valid
        }
        override suspend fun attestKey(backend: String, keyId: String, nonce: String): RemoteAttestKeyResult {
            call("attestKey:$backend:$keyId"); return attestation(nonce)
        }
    }

    private val desktopA = "aa".repeat(32)
    private val desktopB = "bb".repeat(32)
    private val fake = FakeSource()
    private var connected: DesktopSession? = DesktopSession(desktopA, fake)
    private val published = mutableListOf<DesktopKeysState>()
    private val fixedNonce = ByteArray(32) { it.toByte() }
    private val controller = DesktopKeysController(desktopA, { connected }, { fixedNonce }, { published += it })

    private suspend fun openDetail(): DesktopKeysState.Detail {
        controller.open()
        controller.chooseBackend(tpm)
        return controller.chooseKey(key) as DesktopKeysState.Detail
    }

    @Test
    fun `no session shows no session and sends nothing`() = runTest {
        connected = null
        assertEquals(DesktopKeysState.NoSession, controller.open())
        assertEquals(listOf<DesktopKeysState>(DesktopKeysState.NoSession), published)
        assertTrue(fake.calls.isEmpty())
    }

    @Test
    fun `each request shows loading over the previous screen first`() = runTest {
        val backends = controller.open()
        assertEquals(DesktopKeysState.Loading(null), published[0])
        controller.chooseBackend(tpm)
        assertEquals(DesktopKeysState.Loading(backends), published[2])
    }

    @Test
    fun `opening lists the backends`() = runTest {
        assertEquals(DesktopKeysState.Backends(listOf(tpm, soft)), controller.open())
        assertEquals(listOf("listBackends"), fake.calls)
    }

    @Test
    fun `choosing a backend lists its keys`() = runTest {
        controller.open()
        assertEquals(DesktopKeysState.Keys(soft, listOf(key)), controller.chooseBackend(soft))
        assertEquals("listKeys:software", fake.calls.last())
    }

    @Test
    fun `choosing a key shows its info and public key`() = runTest {
        val detail = openDetail()
        assertEquals(DesktopKeysState.Detail(tpm, info, publicKey), detail)
        assertEquals(listOf("getKeyInfo:tpm2:k1", "getPublicKey:tpm2:k1"), fake.calls.takeLast(2))
    }

    @Test
    fun `sign test signs the fixed message and verifies the signature`() = runTest {
        openDetail()
        val detail = controller.signTest() as DesktopKeysState.Detail
        assertEquals(SignTestResult("ecdsa-p256-sha256", "c2ln", true), detail.signTest)
        assertEquals(listOf("sign:tpm2:k1", "verify:tpm2:k1"), fake.calls.takeLast(2))
        assertEquals(
            listOf(Base64.getEncoder().encodeToString("xKey desktop key test".toByteArray()), "c2ln", "ecdsa-p256-sha256"),
            fake.lastVerify
        )
    }

    @Test
    fun `sign test reports a signature the desktop does not verify`() = runTest {
        openDetail()
        fake.valid = false
        val detail = controller.signTest() as DesktopKeysState.Detail
        assertFalse(detail.signTest!!.valid)
    }

    @Test
    fun `attest shows the result fields and sends a fresh nonce`() = runTest {
        openDetail()
        controller.signTest()
        val detail = controller.attest() as DesktopKeysState.Detail
        val nonce = Base64.getEncoder().encodeToString(fixedNonce)
        assertEquals(AttestationSummary("tpm2", 2, 5, nonce), detail.attestation)
        assertTrue("sign test kept", detail.signTest!!.valid)
        assertEquals("attestKey:tpm2:k1", fake.calls.last())
    }

    @Test
    fun `attest without attestation data counts zero bytes`() = runTest {
        openDetail()
        fake.attestation = { RemoteAttestKeyResult("software", listOf("A"), null, it) }
        val detail = controller.attest() as DesktopKeysState.Detail
        assertEquals(0, detail.attestation!!.attestationDataBytes)
        assertEquals(1, detail.attestation!!.certificateCount)
    }

    @Test
    fun `a desktop error is typed and keeps the previous screen`() = runTest {
        val detail = openDetail()
        fake.failure = ProtocolException("Remote error: denied", errorCode = ErrorCodes.OPERATION_DENIED)
        val failed = controller.signTest() as DesktopKeysState.Failed
        assertEquals(DesktopKeyError.Kind.DENIED, failed.error.kind)
        assertEquals(ErrorCodes.OPERATION_DENIED, failed.error.code)
        assertEquals(detail, failed.previous)

        fake.failure = null
        val retried = controller.signTest() as DesktopKeysState.Detail
        assertTrue(retried.signTest!!.valid)
    }

    @Test
    fun `errors map to their kinds`() {
        fun kind(e: Exception) = DesktopKeyError.from(e).kind
        assertEquals(DesktopKeyError.Kind.KEY_NOT_FOUND, kind(ProtocolException("x", errorCode = ErrorCodes.KEY_NOT_FOUND)))
        assertEquals(DesktopKeyError.Kind.DENIED, kind(ProtocolException("x", errorCode = ErrorCodes.BACKEND_DENIED)))
        assertEquals(DesktopKeyError.Kind.UNSUPPORTED, kind(ProtocolException("x", errorCode = ErrorCodes.METHOD_NOT_FOUND)))
        assertEquals(
            DesktopKeyError.Kind.ATTESTATION_FAILED,
            kind(ProtocolException("x", errorCode = ErrorCodes.ATTESTATION_FAILED))
        )
        assertEquals(DesktopKeyError.Kind.REMOTE, kind(ProtocolException("Request timed out: remote.sign")))
        assertEquals(DesktopKeyError.Kind.TRANSPORT, kind(IOException("broken pipe")))
        assertNull(DesktopKeyError.from(IOException("broken pipe")).code)
    }

    @Test
    fun `cancellation is rethrown and the previous screen restored`() = runTest {
        val backends = controller.open()
        fake.failure = CancellationException("screen closed")
        try {
            controller.chooseBackend(tpm)
            fail("expected cancellation")
        } catch (e: CancellationException) {
            assertEquals("screen closed", e.message)
        }
        assertEquals(backends, controller.state)
        assertTrue(published.none { it is DesktopKeysState.Failed })
    }

    @Test
    fun `back walks up from detail to keys to backends, then closes`() = runTest {
        openDetail()
        assertTrue(controller.back())
        assertEquals(DesktopKeysState.Keys(tpm, listOf(key)), controller.state)
        assertTrue(controller.back())
        assertEquals(DesktopKeysState.Backends(listOf(tpm, soft)), controller.state)
        assertFalse(controller.back())
    }

    @Test
    fun `a session with another desktop at open sends nothing`() = runTest {
        connected = DesktopSession(desktopB, fake)
        assertEquals(DesktopKeysState.NoSession, controller.open())
        assertTrue(fake.calls.isEmpty())
    }

    @Test
    fun `another desktop taking the session gets no request and clears the screen`() = runTest {
        openDetail()
        val other = FakeSource()
        connected = DesktopSession(desktopB, other)
        assertEquals(DesktopKeysState.NoSession, controller.signTest())
        assertTrue(other.calls.isEmpty())
        assertTrue(fake.calls.none { it.startsWith("sign") })
        assertFalse("nothing left to go back to", controller.back())
    }

    @Test
    fun `the client is captured once and a new one is refused`() = runTest {
        controller.open()
        val other = FakeSource()
        connected = DesktopSession(desktopA, other)
        assertEquals(DesktopKeysState.NoSession, controller.chooseBackend(tpm))
        assertTrue(other.calls.isEmpty())
        assertEquals(listOf("listBackends"), fake.calls)
    }

    @Test
    fun `the peer changing between sign and verify stops the verify`() = runTest {
        openDetail()
        fake.onSign = { connected = DesktopSession(desktopB, fake) }
        assertEquals(DesktopKeysState.NoSession, controller.signTest())
        assertTrue(fake.calls.none { it.startsWith("verify") })
        assertEquals(DesktopKeysState.NoSession, controller.state)
    }

    @Test
    fun `the session ending clears the screen`() = runTest {
        controller.open()
        controller.chooseBackend(tpm)
        connected = null
        assertEquals(DesktopKeysState.NoSession, controller.chooseKey(key))
        assertFalse(controller.back())
    }

    /** Over the real client: the screen's first two steps put these methods on the wire. */
    @Test
    fun `opening sends remote listBackends and choosing a backend sends remote listKeys`() = runTest {
        stubAndroidLog()
        try {
            val router = BidirectionalMessageRouter(mockk<RequestHandler>())
            val sender = ScriptedMessageSender(router)
            val session = DesktopSession(desktopA, DesktopKeysSource.of(RemoteKeyClient(sender, router, 5_000L)))
            val wire = DesktopKeysController(desktopA, { session })
            sender.succeedWith(
                """{"backends":[{"name":"tpm2","type":"tpm2","hardwareBacked":true,"signing":true,""" +
                    """"decryption":false,"symmetricCrypto":false,"keyAgreement":false,"attestation":true}]}"""
            )
            val backends = wire.open() as DesktopKeysState.Backends
            assertEquals("remote.listBackends", sender.lastRequest.method)

            sender.succeedWith("""{"keys":[]}""")
            wire.chooseBackend(backends.backends.single())
            assertEquals("remote.listKeys", sender.lastRequest.method)
            assertEquals("tpm2", sender.lastRequest.params!!.getString("backend"))
        } finally {
            unmockkAll()
        }
    }
}
