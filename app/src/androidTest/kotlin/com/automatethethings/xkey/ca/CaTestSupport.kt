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
package com.automatethethings.xkey.ca

import android.content.Context
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.junit.AssumptionViolatedException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * Shared helpers for the [AndroidCA] instrumented suites.
 *
 * The CA signs with Android Keystore keys, but the *requesters* in these tests
 * are ordinary software key pairs: a CSR only needs a public key and a self
 * signature, and keeping the subject key off the Keystore means there is one
 * less alias to clean up per test.
 */
internal object CaTestSupport {

    const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    /** X.509 extension OIDs asserted by the profile tests. */
    const val OID_KEY_USAGE = "2.5.29.15"
    const val OID_BASIC_CONSTRAINTS = "2.5.29.19"
    const val OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14"
    const val OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35"
    const val OID_EXTENDED_KEY_USAGE = "2.5.29.37"
    const val OID_SUBJECT_ALT_NAME = "2.5.29.17"

    /** `KeyUsage` bit positions as returned by [X509Certificate.getKeyUsage]. */
    const val KU_DIGITAL_SIGNATURE = 0
    const val KU_NON_REPUDIATION = 1
    const val KU_KEY_ENCIPHERMENT = 2
    const val KU_KEY_CERT_SIGN = 5
    const val KU_CRL_SIGN = 6

    /** `GeneralName` tag numbers used by [X509Certificate.getSubjectAlternativeNames]. */
    const val SAN_RFC822 = 1
    const val SAN_DNS = 2
    const val SAN_IP = 7

    fun softwareKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()

    /** Builds a valid, self-signed PKCS#10 request for [subject]. */
    fun csr(subject: String, keyPair: KeyPair = softwareKeyPair()): ByteArray =
        JcaPKCS10CertificationRequestBuilder(X500Name(subject), keyPair.public)
            .build(JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(keyPair.private))
            .encoded

    /**
     * Builds a CSR whose signature no longer matches its content.
     *
     * A byte of the subject CN is flipped after signing. Because the mutation is
     * length-preserving and inside a printable string, the DER still parses --
     * only the signature check can catch it, which is exactly the guard under
     * test.
     */
    fun csrWithBrokenSignature(): ByteArray {
        val marker = "TAMPERTARGET"
        val der = csr("CN=$marker")
        val markerBytes = marker.toByteArray(Charsets.US_ASCII)
        val index = indexOf(der, markerBytes)
        require(index >= 0) { "CN marker not found in the encoded CSR" }
        der[index] = 'X'.code.toByte()
        return der
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }

    /** Whole days spanned by a certificate's validity window. */
    fun validityDays(cert: X509Certificate): Long =
        (cert.notAfter.time - cert.notBefore.time) / 86_400_000L

    /**
     * Skips the calling suite when the CA cannot be created on this device.
     *
     * [AndroidCA.generateCAKey] always requests StrongBox and has no runtime
     * fallback, so on hardware (or an emulator image) without a StrongBox
     * keymaster every CA operation is unreachable.
     */
    fun assumeCaGenerated(result: CAInitResult, stage: String) {
        if (result is CAInitResult.Error) {
            throw AssumptionViolatedException(
                "$stage failed on this device: ${result.message}. AndroidCA requests a " +
                    "StrongBox-backed key and falls back to the TEE, so a failure here " +
                    "means neither is usable and CA tests cannot run."
            )
        }
    }

    /**
     * Ensures the shared on-device CA hierarchy exists, building it if it does
     * not, and skips the calling suite when this device cannot host one.
     *
     * The CA lives in the Android Keystore, which is process-wide and outlives
     * any single suite. [AndroidCATest] and [AndroidCAUninitializedTest] both
     * reset it in `@AfterClass` on purpose — they are asserting the pristine
     * state the app ships with — so a suite that needs a *working* CA cannot
     * assume one is there. It has to establish that precondition itself.
     *
     * Skipping this is what makes issuance fail silently: the UI answers an
     * uninitialised CA with a dialog and writes no certificate, so the test
     * sees nothing rather than an error.
     */
    fun ensureInitialized(context: Context, subject: CASubject = DEFAULT_CA_SUBJECT) {
        val ca = AndroidCA(context)
        if (ca.isInitialized()) {
            return
        }
        runBlocking {
            assumeCaGenerated(ca.generateRootCA(subject), "Root CA generation")
            assumeCaGenerated(ca.generateIntermediateCA(subject), "Intermediate CA generation")
        }
    }

    /** Subject used when a suite does not care what the CA is called. */
    val DEFAULT_CA_SUBJECT = CASubject(cn = "xKey Test CA", org = "xKey Tests")
}
