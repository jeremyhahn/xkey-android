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
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.AlgorithmParameters
import java.security.spec.ECParameterSpec

/**
 * TPM 2.0 algorithm identifiers used by device identity enrollment.
 *
 * Values are from TPM 2.0 Library Specification Part 2, Table 9 (TPM_ALG_ID).
 */
object TpmAlg {
    const val RSA = 0x0001
    const val SHA1 = 0x0004
    const val HMAC = 0x0005
    const val AES = 0x0006
    const val SHA256 = 0x000B
    const val SHA384 = 0x000C
    const val SHA512 = 0x000D
    const val NULL = 0x0010
    const val RSASSA = 0x0014
    const val RSAES = 0x0015
    const val RSAPSS = 0x0016
    const val OAEP = 0x0017
    const val ECDSA = 0x0018
    const val ECC = 0x0023
    const val CFB = 0x0043

    /**
     * The JCA digest name for a TPM hash algorithm id, or null when the id is
     * not a hash this code can compute.
     */
    fun digestName(alg: Int): String? = when (alg) {
        SHA1 -> "SHA-1"
        SHA256 -> "SHA-256"
        SHA384 -> "SHA-384"
        SHA512 -> "SHA-512"
        else -> null
    }

    /** The lowercase PCR bank name for a TPM hash algorithm id. */
    fun bankName(alg: Int): String? = when (alg) {
        SHA1 -> "sha1"
        SHA256 -> "sha256"
        SHA384 -> "sha384"
        SHA512 -> "sha512"
        else -> null
    }
}

/**
 * TPMA_OBJECT attribute bits (Part 2, Table 31).
 */
object TpmObjectAttributes {
    const val FIXED_TPM = 1 shl 1
    const val ST_CLEAR = 1 shl 2
    const val FIXED_PARENT = 1 shl 4
    const val SENSITIVE_DATA_ORIGIN = 1 shl 5
    const val USER_WITH_AUTH = 1 shl 6
    const val ADMIN_WITH_POLICY = 1 shl 7
    const val NO_DA = 1 shl 10
    const val ENCRYPTED_DUPLICATION = 1 shl 11
    const val RESTRICTED = 1 shl 16
    const val DECRYPT = 1 shl 17
    const val SIGN_ENCRYPT = 1 shl 18
}

/** Raised when a TPM structure on the wire cannot be understood. */
class TpmStructureException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * A parsed TPMT_PUBLIC public area.
 *
 * The [raw] bytes are retained because the TPM Name — the value a credential is
 * bound to, and the only thing that ties an attestation key to the TPM holding
 * it — is the digest of exactly these bytes. Re-serializing a parsed structure
 * risks a different encoding and therefore a different Name, so it is never done.
 *
 * @property raw The unmodified TPMT_PUBLIC bytes, with no TPM2B size prefix.
 */
class TpmPublicArea private constructor(
    val raw: ByteArray,
    val type: Int,
    val nameAlg: Int,
    val objectAttributes: Int,
    val symmetricAlg: Int,
    val symmetricKeyBits: Int,
    val symmetricMode: Int,
    val scheme: Int,
    val schemeHashAlg: Int,
    val publicKey: PublicKey
) {
    val isRestricted: Boolean get() = objectAttributes and TpmObjectAttributes.RESTRICTED != 0
    val isFixedTPM: Boolean get() = objectAttributes and TpmObjectAttributes.FIXED_TPM != 0
    val isFixedParent: Boolean get() = objectAttributes and TpmObjectAttributes.FIXED_PARENT != 0
    val isSignEncrypt: Boolean get() = objectAttributes and TpmObjectAttributes.SIGN_ENCRYPT != 0
    val isDecrypt: Boolean get() = objectAttributes and TpmObjectAttributes.DECRYPT != 0

    /**
     * The TPM Name of this object: the name algorithm id in big-endian followed
     * by the digest of the public area under that algorithm.
     *
     * TPM 2.0 Library Specification Part 1, Section 16 ("Names").
     */
    fun name(): ByteArray {
        val digestName = TpmAlg.digestName(nameAlg)
            ?: throw TpmStructureException("public area names itself with unsupported hash 0x%04x".format(nameAlg))
        val digest = MessageDigest.getInstance(digestName).digest(raw)
        val out = ByteArrayOutputStream(2 + digest.size)
        out.write((nameAlg ushr 8) and 0xFF)
        out.write(nameAlg and 0xFF)
        out.write(digest)
        return out.toByteArray()
    }

    companion object {
        /**
         * Parses a TPMT_PUBLIC. [bytes] must be the bare structure with no
         * TPM2B size prefix, which is how the TCG-CSR-IDEVID and the
         * `remote.getTCGCSRIDevID` result both carry it.
         */
        fun parse(bytes: ByteArray): TpmPublicArea {
            if (bytes.isEmpty()) throw TpmStructureException("public area is empty")
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
            try {
                val type = buf.short.toInt() and 0xFFFF
                val nameAlg = buf.short.toInt() and 0xFFFF
                val objectAttributes = buf.int
                skip2B(buf) // authPolicy

                var symAlg = TpmAlg.NULL
                var symBits = 0
                var symMode = TpmAlg.NULL
                var scheme = TpmAlg.NULL
                var schemeHash = TpmAlg.NULL
                val publicKey: PublicKey

                when (type) {
                    TpmAlg.RSA -> {
                        symAlg = buf.short.toInt() and 0xFFFF
                        if (symAlg != TpmAlg.NULL) {
                            symBits = buf.short.toInt() and 0xFFFF
                            symMode = buf.short.toInt() and 0xFFFF
                        }
                        scheme = buf.short.toInt() and 0xFFFF
                        if (scheme != TpmAlg.NULL) {
                            schemeHash = buf.short.toInt() and 0xFFFF
                        }
                        val keyBits = buf.short.toInt() and 0xFFFF
                        var exponent = buf.int.toLong() and 0xFFFFFFFFL
                        if (exponent == 0L) exponent = 65537L
                        val modulus = read2B(buf)
                        if (modulus.isEmpty()) throw TpmStructureException("RSA public area carries no modulus")
                        if (modulus.size * 8 != keyBits) {
                            throw TpmStructureException(
                                "RSA modulus is ${modulus.size * 8} bits but the public area declares $keyBits"
                            )
                        }
                        publicKey = KeyFactory.getInstance("RSA").generatePublic(
                            RSAPublicKeySpec(BigInteger(1, modulus), BigInteger.valueOf(exponent))
                        )
                    }

                    TpmAlg.ECC -> {
                        symAlg = buf.short.toInt() and 0xFFFF
                        if (symAlg != TpmAlg.NULL) {
                            symBits = buf.short.toInt() and 0xFFFF
                            symMode = buf.short.toInt() and 0xFFFF
                        }
                        scheme = buf.short.toInt() and 0xFFFF
                        if (scheme != TpmAlg.NULL) {
                            schemeHash = buf.short.toInt() and 0xFFFF
                        }
                        val curveId = buf.short.toInt() and 0xFFFF
                        val kdfScheme = buf.short.toInt() and 0xFFFF
                        if (kdfScheme != TpmAlg.NULL) {
                            buf.short // kdf hash
                        }
                        val x = read2B(buf)
                        val y = read2B(buf)
                        publicKey = eccPublicKey(curveId, x, y)
                    }

                    else -> throw TpmStructureException("unsupported public area type 0x%04x".format(type))
                }

                return TpmPublicArea(
                    raw = bytes.copyOf(),
                    type = type,
                    nameAlg = nameAlg,
                    objectAttributes = objectAttributes,
                    symmetricAlg = symAlg,
                    symmetricKeyBits = symBits,
                    symmetricMode = symMode,
                    scheme = scheme,
                    schemeHashAlg = schemeHash,
                    publicKey = publicKey
                )
            } catch (e: TpmStructureException) {
                throw e
            } catch (e: Exception) {
                throw TpmStructureException("malformed TPMT_PUBLIC: ${e.message}", e)
            }
        }

        /** TCG curve id to JCA curve name (Part 2, Table 12). */
        private fun curveName(curveId: Int): String = when (curveId) {
            0x0003 -> "secp256r1"
            0x0004 -> "secp384r1"
            0x0005 -> "secp521r1"
            else -> throw TpmStructureException("unsupported ECC curve 0x%04x".format(curveId))
        }

        private fun eccPublicKey(curveId: Int, x: ByteArray, y: ByteArray): PublicKey {
            val params = AlgorithmParameters.getInstance("EC").apply {
                init(ECGenParameterSpec(curveName(curveId)))
            }.getParameterSpec(ECParameterSpec::class.java)
            val point = ECPoint(BigInteger(1, x), BigInteger(1, y))
            return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))
        }

        private fun read2B(buf: ByteBuffer): ByteArray {
            val size = buf.short.toInt() and 0xFFFF
            if (size > buf.remaining()) {
                throw TpmStructureException("TPM2B declares $size bytes but only ${buf.remaining()} remain")
            }
            val out = ByteArray(size)
            buf.get(out)
            return out
        }

        private fun skip2B(buf: ByteBuffer) {
            read2B(buf)
        }
    }
}
