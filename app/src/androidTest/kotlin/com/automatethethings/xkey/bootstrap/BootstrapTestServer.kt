/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.bootstrap

import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.IOException
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date

/**
 * A stand-in bootstrap endpoint for the [BootstrapClient] suites.
 *
 * The project has no `mockwebserver` dependency and adding one is out of scope,
 * so the server here is an OkHttp interceptor that answers before a socket is
 * ever opened. That is enough -- and in one respect better than a real server:
 * the SPKI path builds its client with `httpClient.newBuilder()`, which carries
 * the interceptor over, so the pinning branch can be driven without standing up
 * TLS with a matching pin.
 *
 * Requests are recorded so a test can assert the URL the client actually built.
 */
internal class BootstrapTestServer(
    private val respond: (Request) -> Response
) {
    private val recorded = mutableListOf<Request>()

    /** Every request the client issued, in order. */
    val requests: List<Request> get() = synchronized(recorded) { recorded.toList() }

    /** The single request the client issued; fails if there was not exactly one. */
    fun singleRequest(): Request = requests.single()

    fun client(): OkHttpClient = OkHttpClient.Builder()
        .addInterceptor(Interceptor { chain ->
            val request = chain.request()
            synchronized(recorded) { recorded.add(request) }
            respond(request)
        })
        .build()

    companion object {
        private const val PEM_MEDIA_TYPE = "application/x-pem-file"

        /** Answers every request with [body] and HTTP [code]. */
        fun serving(
            body: ByteArray,
            code: Int = 200,
            contentType: String = PEM_MEDIA_TYPE
        ): BootstrapTestServer = BootstrapTestServer { request ->
            Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(code)
                .message(if (code == 200) "OK" else "Error")
                .body(body.toResponseBody(contentType.toMediaType()))
                .build()
        }

        /** Answers every request with [text]. */
        fun serving(text: String, code: Int = 200): BootstrapTestServer =
            serving(text.toByteArray(Charsets.UTF_8), code)

        /** Fails every request at the transport layer. */
        fun failing(message: String = "connection refused"): BootstrapTestServer =
            BootstrapTestServer { throw IOException(message) }

        /**
         * A self-signed EC certificate. Software keys, not Keystore ones, so
         * the suite leaves no aliases behind to clean up.
         */
        fun certificate(commonName: String): X509Certificate {
            val keyPair = KeyPairGenerator.getInstance("EC")
                .apply { initialize(ECGenParameterSpec("secp256r1")) }
                .generateKeyPair()
            val subject = X500Name("CN=$commonName")
            val now = System.currentTimeMillis()
            val holder = JcaX509v3CertificateBuilder(
                subject,
                BigInteger(64, SecureRandom()),
                Date(now - 86_400_000L),
                Date(now + 365L * 86_400_000L),
                subject,
                keyPair.public
            ).build(JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private))
            return JcaX509CertificateConverter().getCertificate(holder)
        }

        /** PEM encoding of [certificate], the shape a real bundle arrives in. */
        fun pem(certificate: X509Certificate): String {
            val body = Base64.getMimeEncoder(64, "\n".toByteArray())
                .encodeToString(certificate.encoded)
            return "-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----\n"
        }

        /** A bundle of [count] freshly generated certificates. */
        fun bundle(count: Int): String =
            (1..count).joinToString("") { pem(certificate("Bundle Anchor $it")) }
    }
}
