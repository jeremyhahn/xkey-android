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
package com.automatethethings.xkey.ui

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * Produces real X.509 certificates for instrumented UI tests.
 *
 * Screens such as [TrustStoreActivity], [CertificateDetailActivity] and
 * [PivSlotDetailActivity] parse DER/PEM with `CertificateFactory`, so a
 * hand-rolled byte array will not do. Android Keystore self-signs a certificate
 * as a side effect of key generation, and [KeyGenParameterSpec.Builder] lets the
 * subject and validity window be chosen, which is enough to drive the valid /
 * expiring / expired rendering paths without pulling in a certificate builder.
 *
 * Every generated key lives under a caller-supplied alias; tests must call
 * [deleteAlias] in their teardown so the shared Android Keystore stays clean.
 */
object TestCertificates {

    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

    /** One day in milliseconds. */
    const val ONE_DAY_MS = 86_400_000L

    /**
     * Generates an EC key under [alias] and returns its self-signed certificate.
     *
     * @param alias Android Keystore alias; use a test-unique value.
     * @param commonName Certificate subject CN.
     * @param notBefore Start of the validity window.
     * @param notAfter End of the validity window; may be in the past to build an
     *   already-expired certificate.
     */
    fun selfSigned(
        alias: String,
        commonName: String,
        notBefore: Date = Date(System.currentTimeMillis() - ONE_DAY_MS),
        notAfter: Date = Date(System.currentTimeMillis() + 365L * ONE_DAY_MS)
    ): X509Certificate {
        deleteAlias(alias)

        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            KEYSTORE_PROVIDER
        )
        generator.initialize(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setCertificateSubject(X500Principal("CN=$commonName"))
                .setCertificateNotBefore(notBefore)
                .setCertificateNotAfter(notAfter)
                .build()
        )
        generator.generateKeyPair()

        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        return keyStore.getCertificate(alias) as X509Certificate
    }

    /** Encodes [certificate] as a PEM block. */
    fun toPem(certificate: X509Certificate): String {
        val body = Base64.encodeToString(certificate.encoded, Base64.NO_WRAP)
            .chunked(64)
            .joinToString("\n")
        return "-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----\n"
    }

    /** Removes [alias] from the Android Keystore, ignoring absence. */
    fun deleteAlias(alias: String) {
        runCatching {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        }
    }
}
