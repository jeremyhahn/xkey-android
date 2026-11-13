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
package com.automatethethings.xkey.truststore

import android.util.Log
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.zip.GZIPOutputStream
import kotlinx.coroutines.test.runTest
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.asResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import okio.GzipSource
import okio.buffer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for [CABundleFetcher].
 *
 * Rather than mocking OkHttp, each test installs an application interceptor that
 * short-circuits the call with a canned response. That keeps the real `Request`
 * construction (URL normalisation, `Accept` header) under test while never
 * touching the network, and lets the captured requests be asserted on.
 *
 * The PEM parser is the security-relevant part here: it must extract exactly the
 * certificates present, skip malformed blocks instead of aborting, and fail loudly
 * when a response carries nothing parseable.
 */
class CABundleFetcherTest {

    private val capturedRequests = mutableListOf<Request>()

    @Before
    fun setUp() {
        capturedRequests.clear()
        mockkStatic(Log::class)
        every { Log.i(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // -------------------------------------------------------------------------
    // Request construction
    // -------------------------------------------------------------------------

    @Test
    fun `fetchBundle appends the ca-bundle endpoint and Accept header`() = runTest {
        val fetcher = fetcherReturning(body = TestCertificates.ROOT_CA_A_PEM)

        fetcher.fetchBundle("https://ca.example.com")

        assertEquals(1, capturedRequests.size)
        val request = capturedRequests.single()
        assertEquals("https://ca.example.com/acme/ca-bundle", request.url.toString())
        assertEquals("GET", request.method)
        assertEquals("application/pem-certificate-chain", request.header("Accept"))
    }

    @Test
    fun `fetchBundle strips trailing slashes from the base URL`() = runTest {
        val fetcher = fetcherReturning(body = TestCertificates.ROOT_CA_A_PEM)

        fetcher.fetchBundle("https://ca.example.com///")

        assertEquals(
            "https://ca.example.com/acme/ca-bundle",
            capturedRequests.single().url.toString()
        )
    }

    // -------------------------------------------------------------------------
    // Successful responses
    // -------------------------------------------------------------------------

    @Test
    fun `fetchBundle parses every certificate in the bundle in order`() = runTest {
        val body = TestCertificates.INTERMEDIATE_A_PEM + TestCertificates.ROOT_CA_A_PEM
        val fetcher = fetcherReturning(body = body)

        val result = fetcher.fetchBundle("https://ca.example.com")

        assertEquals(2, result.certificates.size)
        assertTrue(
            result.certificates[0].subjectX500Principal.name
                .startsWith(TestCertificates.INTERMEDIATE_A_CN)
        )
        assertTrue(
            result.certificates[1].subjectX500Principal.name
                .startsWith(TestCertificates.ROOT_A_CN)
        )
        assertEquals(
            TestCertificates.sha256Hex(body.toByteArray()),
            TestCertificates.sha256Hex(result.pemBundle)
        )
    }

    @Test
    fun `fetchBundle returns the Cache-Control header when present`() = runTest {
        val fetcher = fetcherReturning(
            body = TestCertificates.ROOT_CA_A_PEM,
            headers = mapOf(
                "Content-Type" to "application/pem-certificate-chain",
                "Cache-Control" to "max-age=3600"
            )
        )

        val result = fetcher.fetchBundle("https://ca.example.com")

        assertEquals("max-age=3600", result.cacheControl)
    }

    @Test
    fun `fetchBundle reports a null Cache-Control when the header is absent`() = runTest {
        val fetcher = fetcherReturning(body = TestCertificates.ROOT_CA_A_PEM)

        assertNull(fetcher.fetchBundle("https://ca.example.com").cacheControl)
    }

    @Test
    fun `fetchBundle still parses when the Content-Type is unexpected`() = runTest {
        val fetcher = fetcherReturning(
            body = TestCertificates.ROOT_CA_A_PEM,
            headers = mapOf("Content-Type" to "text/plain")
        )

        val result = fetcher.fetchBundle("https://ca.example.com")

        assertEquals(1, result.certificates.size)
    }

    @Test
    fun `fetchBundle ignores text surrounding the PEM blocks`() = runTest {
        val body = "# xKey CA bundle\n" +
            TestCertificates.ROOT_CA_A_PEM +
            "\n# trailing commentary\n"
        val fetcher = fetcherReturning(body = body)

        val result = fetcher.fetchBundle("https://ca.example.com")

        assertEquals(1, result.certificates.size)
        assertTrue(
            result.certificates[0].subjectX500Principal.name
                .startsWith(TestCertificates.ROOT_A_CN)
        )
    }

    @Test
    fun `fetchBundle skips a malformed PEM block but keeps the valid ones`() = runTest {
        val body = "-----BEGIN CERTIFICATE-----\nnot base64 at all!!\n-----END CERTIFICATE-----\n" +
            TestCertificates.ROOT_CA_A_PEM
        val fetcher = fetcherReturning(body = body)

        val result = fetcher.fetchBundle("https://ca.example.com")

        assertEquals(1, result.certificates.size)
        assertTrue(
            result.certificates[0].subjectX500Principal.name
                .startsWith(TestCertificates.ROOT_A_CN)
        )
    }

    // -------------------------------------------------------------------------
    // Failures
    // -------------------------------------------------------------------------

    @Test
    fun `fetchBundle fails on a non-success status`() = runTest {
        val fetcher = fetcherReturning(code = 404, message = "Not Found", body = "nope")

        val error = assertFails(CABundleFetchException::class.java) {
            fetcher.fetchBundle("https://ca.example.com")
        }

        assertTrue(
            "unexpected message: ${error.message}",
            error.message!!.contains("HTTP 404")
        )
    }

    @Test
    fun `fetchBundle wraps network errors`() = runTest {
        val fetcher = CABundleFetcher(
            OkHttpClient.Builder()
                .addInterceptor(Interceptor { throw IOException("connection reset") })
                .build()
        )

        val error = assertFails(CABundleFetchException::class.java) {
            fetcher.fetchBundle("https://ca.example.com")
        }

        assertTrue(error.message!!.contains("Network error fetching CA bundle"))
        // fetchBundle runs in withContext, and kotlinx-coroutines stack-trace
        // recovery rethrows a copy carrying the original as its cause, so the
        // IOException sits deeper than one level. Walk the chain.
        val causes = generateSequence(error.cause) { it.cause }.map { it.message }.toList()
        assertTrue(
            "original cause missing from chain: $causes",
            causes.any { it == "connection reset" }
        )
    }

    @Test
    fun `fetchBundle fails when the body holds no PEM blocks`() = runTest {
        val fetcher = fetcherReturning(body = "<html>not a bundle</html>")

        val error = assertFails(CABundleFetchException::class.java) {
            fetcher.fetchBundle("https://ca.example.com")
        }

        assertTrue(error.message!!.contains("No valid certificates found"))
    }

    @Test
    fun `fetchBundle fails when a PEM block is never terminated`() = runTest {
        val fetcher = fetcherReturning(
            body = "-----BEGIN CERTIFICATE-----\nMIIBwjCCAWmgAwIBAgIUFbGe1x87FyWohyUN\n"
        )

        val error = assertFails(CABundleFetchException::class.java) {
            fetcher.fetchBundle("https://ca.example.com")
        }

        assertTrue(error.message!!.contains("No valid certificates found"))
    }

    // -------------------------------------------------------------------------
    // CABundleResult value semantics
    // -------------------------------------------------------------------------

    @Test
    fun `CABundleResult compares by content`() {
        val certs = listOf(TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM))
        val a = CABundleResult("pem".toByteArray(), certs, "max-age=60")
        val b = CABundleResult("pem".toByteArray(), certs, "max-age=60")
        val different = CABundleResult("other".toByteArray(), certs, "max-age=60")

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertTrue(a != different)
        assertTrue(a != Any())
    }

    // -------------------------------------------------------------------------
    // Response size and certificate count limits
    // -------------------------------------------------------------------------

    @Test
    fun `fetchBundle refuses a body one byte over the size limit`() = runTest {
        val fetcher = fetcherReturning(body = paddedBundle(MAX_BODY_BYTES + 1))

        val error = assertFails(CABundleFetchException::class.java) {
            fetcher.fetchBundle("https://ca.example.com")
        }

        assertTrue(
            "unexpected message: ${error.message}",
            error.message!!.contains("too large")
        )
    }

    @Test
    fun `fetchBundle parses a body of exactly the size limit`() = runTest {
        val body = paddedBundle(MAX_BODY_BYTES)
        val fetcher = fetcherReturning(body = body)

        val result = fetcher.fetchBundle("https://ca.example.com")

        assertEquals(MAX_BODY_BYTES, result.pemBundle.size)
        assertEquals(1, result.certificates.size)
    }

    @Test
    fun `fetchBundle refuses a gzip body that inflates past the size limit`() = runTest {
        val compressed = ByteArrayOutputStream().also { out ->
            GZIPOutputStream(out).use { it.write(paddedBundle(2 * MAX_BODY_BYTES).toByteArray()) }
        }.toByteArray()
        assertTrue(compressed.size < MAX_BODY_BYTES)
        // OkHttp's bridge strips Content-Encoding and hands the caller the
        // inflating source; the limit must hold on what that source yields.
        val decoded = GzipSource(Buffer().write(compressed)).buffer()
            .asResponseBody("application/pem-certificate-chain".toMediaTypeOrNull(), -1)
        val fetcher = fetcherReturningBody(decoded)

        val error = assertFails(CABundleFetchException::class.java) {
            fetcher.fetchBundle("https://ca.example.com")
        }

        assertTrue(
            "unexpected message: ${error.message}",
            error.message!!.contains("too large")
        )
    }

    @Test
    fun `fetchBundle refuses a bundle over the certificate limit before parsing`() = runTest {
        // Malformed blocks would be skipped by the parser and end in "No valid
        // certificates found"; the count check must fire first.
        val malformed = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        val fetcher = fetcherReturning(body = malformed.repeat(MAX_CERTIFICATES + 1))

        val error = assertFails(CABundleFetchException::class.java) {
            fetcher.fetchBundle("https://ca.example.com")
        }

        assertTrue(
            "unexpected message: ${error.message}",
            error.message!!.contains("limit is $MAX_CERTIFICATES")
        )
    }

    @Test
    fun `fetchBundle parses a bundle at the certificate limit`() = runTest {
        val fetcher = fetcherReturning(body = TestCertificates.ROOT_CA_A_PEM.repeat(MAX_CERTIFICATES))

        val result = fetcher.fetchBundle("https://ca.example.com")

        assertEquals(MAX_CERTIFICATES, result.certificates.size)
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** One valid certificate followed by comment padding, [size] bytes in all. */
    private fun paddedBundle(size: Int): String {
        val pem = TestCertificates.ROOT_CA_A_PEM + "\n"
        return pem + "#".repeat(size - pem.toByteArray().size)
    }

    private fun fetcherReturningBody(body: ResponseBody): CABundleFetcher {
        val interceptor = Interceptor { chain ->
            capturedRequests.add(chain.request())
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .header("Content-Type", "application/pem-certificate-chain")
                .body(body)
                .build()
        }
        return CABundleFetcher(OkHttpClient.Builder().addInterceptor(interceptor).build())
    }

    private fun fetcherReturning(
        code: Int = 200,
        message: String = "OK",
        body: String,
        headers: Map<String, String> = mapOf("Content-Type" to "application/pem-certificate-chain")
    ): CABundleFetcher {
        val interceptor = Interceptor { chain ->
            capturedRequests.add(chain.request())
            val builder = Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(code)
                .message(message)
                .body(
                    body.toByteArray().toResponseBody(
                        "application/pem-certificate-chain".toMediaTypeOrNull()
                    )
                )
            headers.forEach { (name, value) -> builder.header(name, value) }
            builder.build()
        }
        return CABundleFetcher(OkHttpClient.Builder().addInterceptor(interceptor).build())
    }

    /** Assert that [block] fails with [type], without nesting a blocking dispatcher. */
    private suspend fun <T : Throwable> assertFails(type: Class<T>, block: suspend () -> Unit): T {
        try {
            block()
        } catch (e: Throwable) {
            if (type.isInstance(e)) return type.cast(e)!!
            throw AssertionError("expected ${type.name} but was ${e.javaClass.name}: ${e.message}", e)
        }
        throw AssertionError("expected ${type.name} but nothing was thrown")
    }

    private companion object {
        // The limits CABundleFetcher applies, restated so the tests pin them.
        const val MAX_BODY_BYTES = 1024 * 1024
        const val MAX_CERTIFICATES = 64
    }
}
