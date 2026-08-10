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

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Builders for the TPM wire structures these tests need.
 *
 * The desktop's TPM produces them and an emulator has none, so the structures
 * are assembled here byte for byte against the TPM 2.0 Library Specification
 * Part 2 encodings. That is deliberate: a builder that shared code with the
 * parser would agree with it by construction and prove nothing.
 */
object TpmTestStructures {

    /** Attributes the TCG specification requires of an IAK. */
    const val IAK_ATTRIBUTES = TpmObjectAttributes.FIXED_TPM or
        TpmObjectAttributes.FIXED_PARENT or
        TpmObjectAttributes.SENSITIVE_DATA_ORIGIN or
        TpmObjectAttributes.USER_WITH_AUTH or
        TpmObjectAttributes.RESTRICTED or
        TpmObjectAttributes.SIGN_ENCRYPT

    /** Attributes the TCG specification requires of an IDevID. */
    const val IDEVID_ATTRIBUTES = TpmObjectAttributes.FIXED_TPM or
        TpmObjectAttributes.FIXED_PARENT or
        TpmObjectAttributes.SENSITIVE_DATA_ORIGIN or
        TpmObjectAttributes.USER_WITH_AUTH or
        TpmObjectAttributes.SIGN_ENCRYPT

    fun generateEcKeyPair(curve: String = "secp256r1"): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec(curve))
        }.generateKeyPair()

    fun generateRsaKeyPair(bits: Int = 2048): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()

    /**
     * A TPMT_PUBLIC over an EC signing key.
     */
    fun eccPublicArea(
        key: ECPublicKey,
        objectAttributes: Int,
        nameAlg: Int = TpmAlg.SHA256,
        scheme: Int = TpmAlg.ECDSA,
        schemeHash: Int = TpmAlg.SHA256,
        curveId: Int = 0x0003,
        coordinateSize: Int = 32
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.writeU16(TpmAlg.ECC)
        out.writeU16(nameAlg)
        out.writeU32(objectAttributes)
        out.write2B(ByteArray(0))            // authPolicy
        out.writeU16(TpmAlg.NULL)            // symmetric: none on a signing key
        out.writeU16(scheme)
        if (scheme != TpmAlg.NULL) out.writeU16(schemeHash)
        out.writeU16(curveId)
        out.writeU16(TpmAlg.NULL)            // kdf
        out.write2B(fixed(key.w.affineX, coordinateSize))
        out.write2B(fixed(key.w.affineY, coordinateSize))
        return out.toByteArray()
    }

    /**
     * A TPMT_PUBLIC over an RSA signing key.
     */
    fun rsaPublicArea(
        key: RSAPublicKey,
        objectAttributes: Int,
        nameAlg: Int = TpmAlg.SHA256,
        scheme: Int = TpmAlg.RSASSA,
        schemeHash: Int = TpmAlg.SHA256
    ): ByteArray {
        val modulus = unsigned(key.modulus)
        val out = ByteArrayOutputStream()
        out.writeU16(TpmAlg.RSA)
        out.writeU16(nameAlg)
        out.writeU32(objectAttributes)
        out.write2B(ByteArray(0))
        out.writeU16(TpmAlg.NULL)            // symmetric
        out.writeU16(scheme)
        if (scheme != TpmAlg.NULL) out.writeU16(schemeHash)
        out.writeU16(modulus.size * 8)       // keyBits
        out.writeU32(key.publicExponent.toInt())
        out.write2B(modulus)
        return out.toByteArray()
    }

    /**
     * The contents block of a TCG-CSR-IDEVID: sixteen big-endian uint32 sizes
     * followed by the fields they describe, in declaration order.
     */
    fun csrContents(
        hashAlgId: Int = TpmAlg.SHA256,
        prodModel: ByteArray = "TEST-MODEL".toByteArray(),
        prodSerial: ByteArray = "TEST-SERIAL".toByteArray(),
        prodCaData: ByteArray = ByteArray(0),
        bootEventLog: ByteArray = ByteArray(0),
        ekCert: ByteArray = ByteArray(0),
        attestPub: ByteArray,
        atCreateTicket: ByteArray = ByteArray(0),
        atCertifyInfo: ByteArray = ByteArray(0),
        atCertifyInfoSig: ByteArray = ByteArray(0),
        signingPub: ByteArray,
        sgnCertifyInfo: ByteArray = ByteArray(0),
        sgnCertifyInfoSig: ByteArray = ByteArray(0),
        pad: ByteArray = ByteArray(0)
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.writeU32(0x0100_0000)            // contents StructVer
        out.writeU32(hashAlgId)
        out.writeU32(32)                     // HashSz
        out.writeU32(prodModel.size)
        out.writeU32(prodSerial.size)
        out.writeU32(prodCaData.size)
        out.writeU32(bootEventLog.size)
        out.writeU32(ekCert.size)
        out.writeU32(attestPub.size)
        out.writeU32(atCreateTicket.size)
        out.writeU32(atCertifyInfo.size)
        out.writeU32(atCertifyInfoSig.size)
        out.writeU32(signingPub.size)
        out.writeU32(sgnCertifyInfo.size)
        out.writeU32(sgnCertifyInfoSig.size)
        out.writeU32(pad.size)
        listOf(
            prodModel, prodSerial, prodCaData, bootEventLog, ekCert, attestPub,
            atCreateTicket, atCertifyInfo, atCertifyInfoSig, signingPub,
            sgnCertifyInfo, sgnCertifyInfoSig, pad
        ).forEach { out.write(it) }
        return out.toByteArray()
    }

    /** Wraps [contents] and [signature] into a packed TCG-CSR-IDEVID. */
    fun packCsr(contents: ByteArray, signature: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.writeU32(0x0100_0000)            // StructVer
        out.writeU32(1)                      // Contents
        out.writeU32(signature.size)
        out.write(contents)
        out.write(signature)
        return out.toByteArray()
    }

    /**
     * A TPMS_ATTEST holding a quote, as the desktop's `quoted` field carries it.
     */
    fun quoteAttest(
        qualifiedSigner: ByteArray,
        extraData: ByteArray,
        pcrDigest: ByteArray = ByteArray(32) { it.toByte() },
        magic: Int = TpmAttest.TPM_GENERATED,
        type: Int = TpmAttest.ST_ATTEST_QUOTE
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.writeU32(magic)
        out.writeU16(type)
        out.write2B(qualifiedSigner)
        out.write2B(extraData)
        out.write(ByteArray(8))              // clock
        out.writeU32(1)                      // resetCount
        out.writeU32(2)                      // restartCount
        out.write(byteArrayOf(1))            // safe
        out.write(ByteArray(8))              // firmwareVersion
        out.writeU32(1)                      // one PCR selection
        out.writeU16(TpmAlg.SHA256)
        out.write(byteArrayOf(3))            // sizeofSelect
        out.write(byteArrayOf(0xFF.toByte(), 0, 0))
        out.write2B(pcrDigest)
        return out.toByteArray()
    }

    /**
     * Builds the TPMS_ATTEST a TPM2_Certify produces.
     *
     * Shares the header with [quoteAttest] and differs only in the trailing
     * union: a certification carries the certified object's Name and qualified
     * Name where a quote carries a PCR selection and digest.
     */
    fun certifyAttest(
        qualifiedSigner: ByteArray,
        certifiedName: ByteArray,
        extraData: ByteArray = ByteArray(0),
        magic: Int = TpmAttest.TPM_GENERATED,
        type: Int = TpmAttest.ST_ATTEST_CERTIFY
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.writeU32(magic)
        out.writeU16(type)
        out.write2B(qualifiedSigner)
        out.write2B(extraData)
        out.write(ByteArray(8))              // clock
        out.writeU32(1)                      // resetCount
        out.writeU32(2)                      // restartCount
        out.write(byteArrayOf(1))            // safe
        out.write(ByteArray(8))              // firmwareVersion
        out.write2B(certifiedName)           // TPMS_CERTIFY_INFO.name
        out.write2B(certifiedName)           // ... qualifiedName
        return out.toByteArray()
    }

    private fun unsigned(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        return if (bytes[0].toInt() == 0) bytes.copyOfRange(1, bytes.size) else bytes
    }

    private fun fixed(value: BigInteger, size: Int): ByteArray {
        val bytes = unsigned(value)
        if (bytes.size == size) return bytes
        require(bytes.size < size) { "coordinate is wider than $size bytes" }
        return ByteArray(size - bytes.size) + bytes
    }

    private fun ByteArrayOutputStream.writeU16(value: Int) {
        write((value ushr 8) and 0xFF)
        write(value and 0xFF)
    }

    private fun ByteArrayOutputStream.writeU32(value: Int) {
        write((value ushr 24) and 0xFF)
        write((value ushr 16) and 0xFF)
        write((value ushr 8) and 0xFF)
        write(value and 0xFF)
    }

    private fun ByteArrayOutputStream.write2B(value: ByteArray) {
        writeU16(value.size)
        write(value)
    }
}

/** Decodes a hex string; the reference vectors are all given in hex. */
fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "hex string has an odd length" }
    return ByteArray(hex.length / 2) {
        ((Character.digit(hex[it * 2], 16) shl 4) or Character.digit(hex[it * 2 + 1], 16)).toByte()
    }
}

/** Encodes bytes as lowercase hex, for readable assertion failures. */
fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
