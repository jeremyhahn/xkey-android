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
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.IOException
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date

/**
 * A certificate together with the key pair that owns it, so a test can both
 * present the certificate and issue further certificates beneath it.
 */
internal class TestCertificate(
    val certificate: X509Certificate,
    val keyPair: KeyPair,
    val subject: X500Name
)

/**
 * Minimal X.509 fixtures for the JVM bootstrap suites.
 *
 * The DANE paths need chains that really validate -- a DANE-TA record is only
 * satisfied when the leaf PKIX-validates up to the asserted anchor -- so the
 * certificates here are generated with BouncyCastle rather than hard-coded, and
 * the CA carries the basic constraints and key usage PKIX insists on.
 */
internal object TestPki {

    private const val DAY_MILLIS = 86_400_000L

    /** A fresh secp256r1 key pair. */
    fun ecKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    /**
     * A self-signed certificate for [commonName], optionally usable as a CA and
     * optionally carrying dNSName SANs.
     */
    fun selfSigned(
        commonName: String,
        dnsNames: List<String> = emptyList(),
        emailNames: List<String> = emptyList(),
        isCa: Boolean = false,
        keyPair: KeyPair = ecKeyPair()
    ): TestCertificate = issue(
        commonName = commonName,
        dnsNames = dnsNames,
        emailNames = emailNames,
        isCa = isCa,
        subjectKeyPair = keyPair,
        issuerName = X500Name("CN=$commonName"),
        issuerKey = keyPair
    )

    /** A leaf certificate for [commonName] issued by [issuer]. */
    fun issuedBy(
        issuer: TestCertificate,
        commonName: String,
        dnsNames: List<String> = emptyList()
    ): TestCertificate = issue(
        commonName = commonName,
        dnsNames = dnsNames,
        emailNames = emptyList(),
        isCa = false,
        subjectKeyPair = ecKeyPair(),
        issuerName = issuer.subject,
        issuerKey = issuer.keyPair
    )

    private fun issue(
        commonName: String,
        dnsNames: List<String>,
        emailNames: List<String>,
        isCa: Boolean,
        subjectKeyPair: KeyPair,
        issuerName: X500Name,
        issuerKey: KeyPair
    ): TestCertificate {
        val now = System.currentTimeMillis()
        val subject = X500Name("CN=$commonName")
        val builder = JcaX509v3CertificateBuilder(
            issuerName,
            BigInteger(64, SecureRandom()),
            Date(now - DAY_MILLIS),
            Date(now + 365L * DAY_MILLIS),
            subject,
            subjectKeyPair.public
        )
        if (isCa) {
            builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
            builder.addExtension(
                Extension.keyUsage,
                true,
                KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign)
            )
        }
        val alternativeNames = dnsNames.map { GeneralName(GeneralName.dNSName, it) } +
            emailNames.map { GeneralName(GeneralName.rfc822Name, it) }
        if (alternativeNames.isNotEmpty()) {
            builder.addExtension(
                Extension.subjectAlternativeName,
                false,
                GeneralNames(alternativeNames.toTypedArray())
            )
        }
        val holder = builder.build(
            JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.private)
        )
        return TestCertificate(
            JcaX509CertificateConverter().getCertificate(holder),
            subjectKeyPair,
            subject
        )
    }

    /** PEM encoding of [certificate], the shape a real bundle arrives in. */
    fun pem(certificate: X509Certificate): String {
        val body = Base64.getMimeEncoder(64, "\n".toByteArray())
            .encodeToString(certificate.encoded)
        return "-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----\n"
    }

    /** A bundle of [count] freshly generated self-signed certificates. */
    fun bundle(count: Int): String =
        (1..count).joinToString("") { pem(selfSigned("JVM Bundle Anchor $it").certificate) }
}

/**
 * A stand-in HTTPS bootstrap endpoint for the JVM suites.
 *
 * Like [BootstrapTestServer], this is an OkHttp interceptor
 * rather than a socket listener, which matters for DANE: `createDaneHttpClient`
 * derives its client with `httpClient.newBuilder()`, so the interceptor is
 * carried over and the whole DANE fetch branch can be driven without standing up
 * a TLS server whose chain happens to match a TLSA record.
 */
internal class StubBootstrapEndpoint(
    private val respond: (Request) -> Response
) {
    private val recorded = mutableListOf<Request>()

    /** Every request the client issued, in order. */
    val requests: List<Request> get() = synchronized(recorded) { recorded.toList() }

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
        fun serving(body: ByteArray, code: Int = 200): StubBootstrapEndpoint =
            StubBootstrapEndpoint { request ->
                Response.Builder()
                    .request(request)
                    .protocol(Protocol.HTTP_1_1)
                    .code(code)
                    .message(if (code == 200) "OK" else "Error")
                    .body(body.toResponseBody(PEM_MEDIA_TYPE.toMediaType()))
                    .build()
            }

        /** Answers every request with [text]. */
        fun serving(text: String, code: Int = 200): StubBootstrapEndpoint =
            serving(text.toByteArray(Charsets.UTF_8), code)

        /** Fails every request at the transport layer. */
        fun failing(message: String = "connection refused"): StubBootstrapEndpoint =
            StubBootstrapEndpoint { throw IOException(message) }
    }
}
