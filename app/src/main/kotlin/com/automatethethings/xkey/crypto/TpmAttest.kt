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
package com.automatethethings.xkey.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

/** Raised when an attestation quote is malformed or does not verify. */
class TpmQuoteException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * The fields of a TPMS_ATTEST that a Certificate Authority checks.
 *
 * Layout is TPM 2.0 Library Specification Part 2, Table 129:
 * `magic || type || qualifiedSigner || extraData || clockInfo || firmwareVersion
 * || attested`. Only a quote is understood here; the other attestation types
 * carry a differently shaped `attested` union.
 *
 * @property qualifiedSigner The Name of the key that signed. Comparing this to
 *   the IAK's own Name is what stops a quote signed by some other key in the
 *   same TPM from passing.
 * @property extraData The caller's nonce, as the TPM signed it. The echoed
 *   `nonce` field on the wire is unauthenticated; this one is not.
 */
class TpmAttest private constructor(
    val magic: Int,
    val type: Int,
    val qualifiedSigner: ByteArray,
    val extraData: ByteArray,
    val pcrDigest: ByteArray,
    /**
     * The Name of the certified object, for a TPM_ST_ATTEST_CERTIFY.
     *
     * Empty for a quote, which attests PCR state rather than an object.
     */
    val certifiedName: ByteArray = ByteArray(0)
) {
    companion object {
        /** TPM_GENERATED_VALUE; present so a quote can never be a forged hash of chosen data. */
        const val TPM_GENERATED = 0xFF544347.toInt()

        /** TPM_ST_ATTEST_QUOTE. */
        const val ST_ATTEST_QUOTE = 0x8018

        /** TPM_ST_ATTEST_CERTIFY, produced by TPM2_Certify. */
        const val ST_ATTEST_CERTIFY = 0x8017

        private const val CLOCK_INFO_SIZE = 8 + 4 + 4 + 1
        private const val FIRMWARE_VERSION_SIZE = 8

        /**
         * Parses the TPMS_ATTEST carried in a quote result.
         *
         * @param quoted The TPM2B_ATTEST contents, with no size prefix.
         * @throws TpmQuoteException if the structure is not a well-formed quote.
         */
        fun parse(quoted: ByteArray): TpmAttest = parse(quoted, ST_ATTEST_QUOTE)

        /**
         * Parses a TPMS_ATTEST and insists it is of [expectedType].
         *
         * The type is demanded rather than discovered because the `attested`
         * union is shaped differently per type: reading a certified Name out of
         * a quote would be reading whichever bytes happen to sit at that offset.
         * A caller always knows which kind it asked the device for.
         *
         * @param quoted The TPM2B_ATTEST contents, with no size prefix.
         * @throws TpmQuoteException if the structure is malformed or the wrong type.
         */
        fun parse(quoted: ByteArray, expectedType: Int): TpmAttest {
            if (quoted.size < 6) throw TpmQuoteException("attestation is ${quoted.size} bytes, too short")
            val buf = ByteBuffer.wrap(quoted).order(ByteOrder.BIG_ENDIAN)
            try {
                val magic = buf.int
                if (magic != TPM_GENERATED) {
                    // The single field a TPM will not sign over caller-chosen
                    // data. Without it, anything with a signing key could
                    // compose bytes that decode as an attestation.
                    throw TpmQuoteException("attestation does not begin with TPM_GENERATED_VALUE")
                }
                val type = buf.short.toInt() and 0xFFFF
                if (type != expectedType) {
                    throw TpmQuoteException(
                        "attestation is type 0x%04x, expected 0x%04x".format(type, expectedType)
                    )
                }
                val qualifiedSigner = read2B(buf)
                val extraData = read2B(buf)
                buf.position(buf.position() + CLOCK_INFO_SIZE + FIRMWARE_VERSION_SIZE)

                return when (expectedType) {
                    ST_ATTEST_QUOTE -> {
                        // TPMS_QUOTE_INFO: TPML_PCR_SELECTION then the PCR digest.
                        val selectionCount = buf.int
                        if (selectionCount < 0 || selectionCount > 16) {
                            throw TpmQuoteException("quote declares $selectionCount PCR selections")
                        }
                        repeat(selectionCount) {
                            buf.short // hash algorithm
                            val sizeOfSelect = buf.get().toInt() and 0xFF
                            if (sizeOfSelect > buf.remaining()) {
                                throw TpmQuoteException(
                                    "PCR selection bitmap runs past the end of the quote"
                                )
                            }
                            buf.position(buf.position() + sizeOfSelect)
                        }
                        TpmAttest(magic, type, qualifiedSigner, extraData, read2B(buf))
                    }

                    ST_ATTEST_CERTIFY -> {
                        // TPMS_CERTIFY_INFO: name then qualifiedName.
                        val certifiedName = read2B(buf)
                        TpmAttest(
                            magic, type, qualifiedSigner, extraData,
                            pcrDigest = ByteArray(0),
                            certifiedName = certifiedName
                        )
                    }

                    else -> throw TpmQuoteException(
                        "unsupported attestation type 0x%04x".format(expectedType)
                    )
                }
            } catch (e: TpmQuoteException) {
                throw e
            } catch (e: Exception) {
                throw TpmQuoteException("malformed TPMS_ATTEST: ${e.message}", e)
            }
        }

        private fun read2B(buf: ByteBuffer): ByteArray {
            val size = buf.short.toInt() and 0xFFFF
            if (size > buf.remaining()) {
                throw TpmQuoteException("TPM2B declares $size bytes but only ${buf.remaining()} remain")
            }
            val out = ByteArray(size)
            buf.get(out)
            return out
        }
    }
}

/**
 * Verification of a TPM2 attestation quote against the attestation key that
 * claims to have produced it.
 */
object TpmQuoteVerifier {

    /**
     * Checks that [signature] is [iak]'s signature over [quoted], that the quote
     * names [iak] as its signer, and that it is bound to [expectedNonce].
     *
     * @throws TpmQuoteException naming the first thing that did not hold.
     */
    fun verify(
        iak: TpmPublicArea,
        quoted: ByteArray,
        signature: ByteArray,
        expectedNonce: ByteArray
    ): TpmAttest {
        if (quoted.isEmpty()) throw TpmQuoteException("quote carries no attestation structure")
        if (signature.isEmpty()) throw TpmQuoteException("quote carries no signature")

        val attest = TpmAttest.parse(quoted)

        val iakName = iak.name()
        if (!MessageDigest.isEqual(attest.qualifiedSigner, iakName)) {
            throw TpmQuoteException("quote names a signer that is not the IAK")
        }
        if (!MessageDigest.isEqual(attest.extraData, expectedNonce)) {
            throw TpmQuoteException("quote is not bound to the nonce this CA sent")
        }

        verifySignature(iak, quoted, signature, "quote")
        return attest
    }

    /**
     * Checks [signature] is [key]'s signature over [signed], using the scheme
     * the key's own public area declares.
     *
     * Shared by quote and certify verification: both are a signature by a
     * restricted attestation key over a TPMS_ATTEST, and the scheme selection
     * is the fiddly part. [what] names the structure in any failure.
     */
    internal fun verifySignature(
        key: TpmPublicArea,
        signed: ByteArray,
        signature: ByteArray,
        what: String
    ) {
        if (key.schemeHashAlg == TpmAlg.NULL) {
            // A restricted signing key must carry a signing scheme; without one
            // there is no defined digest to verify against.
            throw TpmQuoteException("attestation key declares no signing scheme")
        }
        val digestName = TpmAlg.digestName(key.schemeHashAlg)
            ?: throw TpmQuoteException(
                "attestation key signs with unsupported hash 0x%04x".format(key.schemeHashAlg)
            )
        val jcaHash = digestName.replace("-", "")

        val verifier = when (key.type) {
            TpmAlg.ECC -> Signature.getInstance("${jcaHash}withECDSA")

            TpmAlg.RSA -> if (key.scheme == TpmAlg.RSAPSS) {
                Signature.getInstance("${jcaHash}withRSA/PSS").apply {
                    val saltLength = MessageDigest.getInstance(digestName).digestLength
                    setParameter(
                        PSSParameterSpec(digestName, "MGF1", MGF1ParameterSpec(digestName), saltLength, 1)
                    )
                }
            } else {
                Signature.getInstance("${jcaHash}withRSA")
            }

            else -> throw TpmQuoteException(
                "attestation key type 0x%04x cannot sign".format(key.type)
            )
        }

        verifier.initVerify(key.publicKey)
        verifier.update(signed)
        if (!verifier.verify(signature)) {
            throw TpmQuoteException("$what signature does not verify under the attestation key")
        }
    }
}

/**
 * Verification that an attestation key certified another key in the same TPM.
 *
 * This is what closes the gap between "the IAK is in a genuine TPM" and "the
 * IDevID is in that same TPM". Credential activation proves the former; the
 * CSR's own self-signature proves only that the requester holds the IDevID
 * private key, which is equally true of a key generated in software.
 *
 * Without this check a device can present a genuine endorsement key and a
 * genuine IAK, pass credential activation, and still be issued an IDevID
 * certificate over a software key -- a certificate asserting a hardware device
 * identity that does not exist.
 */
object TpmCertifyVerifier {

    /**
     * Checks that [attester] certified [subject], bound to [expectedNonce].
     *
     * @param certifyInfo The TPMS_ATTEST produced by TPM2_Certify.
     * @param signature The attester's signature over [certifyInfo].
     * @param expectedNonce The qualifying data this CA supplied, or null when
     *   freshness is established elsewhere in the ceremony.
     * @throws TpmQuoteException naming the first thing that did not hold.
     */
    fun verify(
        attester: TpmPublicArea,
        subject: TpmPublicArea,
        certifyInfo: ByteArray,
        signature: ByteArray,
        expectedNonce: ByteArray? = null
    ): TpmAttest {
        if (certifyInfo.isEmpty()) {
            throw TpmQuoteException("the CSR carries no certification for the signing key")
        }
        if (signature.isEmpty()) {
            throw TpmQuoteException("the CSR carries no signature over the certification")
        }

        val attest = TpmAttest.parse(certifyInfo, TpmAttest.ST_ATTEST_CERTIFY)

        // Signed by the key we think signed it, before anything inside is read.
        TpmQuoteVerifier.verifySignature(attester, certifyInfo, signature, "certification")

        if (!MessageDigest.isEqual(attest.qualifiedSigner, attester.name())) {
            throw TpmQuoteException("the certification names a signer that is not the attestation key")
        }

        // The binding. The Name is a digest over the whole public area, so a
        // substituted key cannot keep the same Name.
        if (!MessageDigest.isEqual(attest.certifiedName, subject.name())) {
            throw TpmQuoteException(
                "the certification covers a different key than the one being certified"
            )
        }

        if (expectedNonce != null && !MessageDigest.isEqual(attest.extraData, expectedNonce)) {
            throw TpmQuoteException("the certification is not bound to the nonce this CA sent")
        }

        return attest
    }
}
