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

import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

/** Raised when a TCG-CSR-IDEVID is malformed or fails verification. */
class TcgCsrException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * A parsed TCG-CSR-IDEVID enrollment package.
 *
 * The structure is defined in TCG "TPM 2.0 Keys for Device Identity and
 * Attestation", Section 13.1: three big-endian uint32 headers, a contents block
 * of sixteen uint32 sizes followed by that many variable-length fields, and a
 * trailing signature.
 *
 * [contents] is kept as the exact byte range it occupied in the packed CSR
 * because that is what the device signed. Re-serializing the parsed fields to
 * check the signature would risk a different encoding and a verification that
 * passes or fails for the wrong reason.
 */
class TcgCsrIDevID private constructor(
    val structVer: Int,
    val contentsVersion: Int,
    val hashAlgId: Int,
    val prodModel: ByteArray,
    val prodSerial: ByteArray,
    val prodCaData: ByteArray,
    val bootEventLog: ByteArray,
    val ekCert: ByteArray,
    val attestPub: ByteArray,
    val atCreateTicket: ByteArray,
    val atCertifyInfo: ByteArray,
    val atCertifyInfoSig: ByteArray,
    val signingPub: ByteArray,
    val sgnCertifyInfo: ByteArray,
    val sgnCertifyInfoSig: ByteArray,
    val contents: ByteArray,
    val signature: ByteArray
) {
    /** The IAK public area. */
    val iak: TpmPublicArea by lazy { TpmPublicArea.parse(attestPub) }

    /** The IDevID public area. */
    val idevid: TpmPublicArea by lazy { TpmPublicArea.parse(signingPub) }

    /**
     * The endorsement key certificate carried inside the CSR, accepting either
     * the DER the TPM stores or the PEM some platforms hand out.
     */
    fun ekCertificate(): X509Certificate {
        if (ekCert.isEmpty()) throw TcgCsrException("CSR carries no EK certificate")
        return parseCertificate(ekCert)
    }

    /**
     * Verifies the device's self-signature over the CSR contents with the IDevID
     * key, and checks that both public areas carry the TPMA_OBJECT attributes
     * the TCG specification requires of them.
     *
     * Section 6.2.2, steps a, d and e: the IDevID must be an unrestricted,
     * fixedTPM, fixedParent signing key and the IAK a restricted one. Those bits
     * are what say the private halves cannot leave the TPM; a key without them
     * proves nothing about where it lives, so a CSR carrying one is refused.
     *
     * @throws TcgCsrException with the reason on any failure.
     */
    fun verifySelfSignature() {
        val idevidPub = try {
            idevid
        } catch (e: TpmStructureException) {
            throw TcgCsrException("IDevID public area is unreadable: ${e.message}", e)
        }
        val iakPub = try {
            iak
        } catch (e: TpmStructureException) {
            throw TcgCsrException("IAK public area is unreadable: ${e.message}", e)
        }

        if (!iakPub.isRestricted) throw TcgCsrException("IAK is not a restricted key")
        if (!iakPub.isFixedTPM) throw TcgCsrException("IAK is not fixedTPM")
        if (!iakPub.isFixedParent) throw TcgCsrException("IAK is not fixedParent")
        if (!iakPub.isSignEncrypt) throw TcgCsrException("IAK is not a signing key")

        if (idevidPub.isRestricted) throw TcgCsrException("IDevID is a restricted key")
        if (!idevidPub.isFixedTPM) throw TcgCsrException("IDevID is not fixedTPM")
        if (!idevidPub.isFixedParent) throw TcgCsrException("IDevID is not fixedParent")
        if (!idevidPub.isSignEncrypt) throw TcgCsrException("IDevID is not a signing key")

        if (signature.isEmpty()) throw TcgCsrException("CSR carries no signature")

        val digestName = TpmAlg.digestName(hashAlgId)
            ?: throw TcgCsrException("CSR names unsupported hash algorithm 0x%04x".format(hashAlgId))
        val jcaHash = digestName.replace("-", "")

        val verifier = when (idevidPub.type) {
            TpmAlg.ECC -> Signature.getInstance("${jcaHash}withECDSA")

            TpmAlg.RSA -> if (idevidPub.scheme == TpmAlg.RSAPSS) {
                Signature.getInstance("${jcaHash}withRSA/PSS").apply {
                    val saltLength = java.security.MessageDigest.getInstance(digestName).digestLength
                    setParameter(
                        PSSParameterSpec(digestName, "MGF1", MGF1ParameterSpec(digestName), saltLength, 1)
                    )
                }
            } else {
                // TPMT_RSA_SCHEME of RSASSA, or TPM_ALG_NULL where the signing
                // scheme is chosen at use time; PKCS#1 v1.5 is the default the
                // desktop signs with in either case.
                Signature.getInstance("${jcaHash}withRSA")
            }

            else -> throw TcgCsrException("IDevID key type 0x%04x cannot sign".format(idevidPub.type))
        }

        verifier.initVerify(idevidPub.publicKey)
        verifier.update(contents)
        if (!verifier.verify(signature)) {
            throw TcgCsrException("CSR signature does not verify under the IDevID public key")
        }
    }

    companion object {
        /** Byte offset of the contents block inside a packed CSR. */
        private const val HEADER_SIZE = 12

        /** Number of uint32 size fields at the head of the contents block. */
        private const val SIZE_FIELD_COUNT = 16

        /**
         * Guards against a size field that would have us allocate the heap. No
         * enrollment field is anywhere near this large; an event log is the
         * biggest and runs to tens of kilobytes.
         */
        private const val MAX_FIELD_SIZE = 4 * 1024 * 1024

        /**
         * Parses a packed TCG-CSR-IDEVID.
         *
         * @throws TcgCsrException if the structure is truncated, or a declared
         *   size does not fit the bytes that follow it.
         */
        fun parse(packed: ByteArray): TcgCsrIDevID {
            if (packed.size < HEADER_SIZE + SIZE_FIELD_COUNT * 4) {
                throw TcgCsrException("CSR is ${packed.size} bytes, too short to hold its own header")
            }
            val buf = ByteBuffer.wrap(packed).order(ByteOrder.BIG_ENDIAN)
            val structVer = buf.int
            buf.int // contents type; unused by the CA
            val sigSize = size(buf.int, "signature")

            val contentsStart = buf.position()
            val contentsVersion = buf.int
            val hashAlgId = buf.int
            buf.int // hash size; the algorithm id already fixes it

            val prodModelSz = size(buf.int, "prodModel")
            val prodSerialSz = size(buf.int, "prodSerial")
            val prodCaDataSz = size(buf.int, "prodCaData")
            val bootLogSz = size(buf.int, "bootEventLog")
            val ekCertSz = size(buf.int, "ekCert")
            val attestPubSz = size(buf.int, "attestPub")
            val atCreateTktSz = size(buf.int, "atCreateTicket")
            val atCertifyInfoSz = size(buf.int, "atCertifyInfo")
            val atCertifySigSz = size(buf.int, "atCertifyInfoSig")
            val signingPubSz = size(buf.int, "signingPub")
            val sgnCertifyInfoSz = size(buf.int, "sgnCertifyInfo")
            val sgnCertifySigSz = size(buf.int, "sgnCertifyInfoSig")
            val padSz = size(buf.int, "pad")

            val prodModel = take(buf, prodModelSz, "prodModel")
            val prodSerial = take(buf, prodSerialSz, "prodSerial")
            val prodCaData = take(buf, prodCaDataSz, "prodCaData")
            val bootLog = take(buf, bootLogSz, "bootEventLog")
            val ekCert = take(buf, ekCertSz, "ekCert")
            val attestPub = take(buf, attestPubSz, "attestPub")
            val atCreateTkt = take(buf, atCreateTktSz, "atCreateTicket")
            val atCertifyInfo = take(buf, atCertifyInfoSz, "atCertifyInfo")
            val atCertifySig = take(buf, atCertifySigSz, "atCertifyInfoSig")
            val signingPub = take(buf, signingPubSz, "signingPub")
            val sgnCertifyInfo = take(buf, sgnCertifyInfoSz, "sgnCertifyInfo")
            val sgnCertifySig = take(buf, sgnCertifySigSz, "sgnCertifyInfoSig")
            take(buf, padSz, "pad")

            val contentsEnd = buf.position()
            val signature = take(buf, sigSize, "signature")

            return TcgCsrIDevID(
                structVer = structVer,
                contentsVersion = contentsVersion,
                hashAlgId = hashAlgId,
                prodModel = prodModel,
                prodSerial = prodSerial,
                prodCaData = prodCaData,
                bootEventLog = bootLog,
                ekCert = ekCert,
                attestPub = attestPub,
                atCreateTicket = atCreateTkt,
                atCertifyInfo = atCertifyInfo,
                atCertifyInfoSig = atCertifySig,
                signingPub = signingPub,
                sgnCertifyInfo = sgnCertifyInfo,
                sgnCertifyInfoSig = sgnCertifySig,
                contents = packed.copyOfRange(contentsStart, contentsEnd),
                signature = signature
            )
        }

        /** Parses a certificate given as either DER or PEM. */
        fun parseCertificate(bytes: ByteArray): X509Certificate {
            val factory = CertificateFactory.getInstance("X.509")
            return try {
                factory.generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate
            } catch (e: Exception) {
                throw TcgCsrException("certificate does not parse as X.509: ${e.message}", e)
            }
        }

        private fun size(value: Int, field: String): Int {
            if (value < 0 || value > MAX_FIELD_SIZE) {
                throw TcgCsrException("CSR field '$field' declares an implausible size")
            }
            return value
        }

        private fun take(buf: ByteBuffer, size: Int, field: String): ByteArray {
            if (size > buf.remaining()) {
                throw TcgCsrException(
                    "CSR field '$field' wants $size bytes but only ${buf.remaining()} remain"
                )
            }
            val out = ByteArray(size)
            buf.get(out)
            return out
        }
    }
}
