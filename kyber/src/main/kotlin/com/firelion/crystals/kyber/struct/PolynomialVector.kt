package com.firelion.crystals.kyber.struct

import com.firelion.crystals.kyber.util.KyberParams
import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_N
import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_POLYNOMIAL_BYTES
import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_Q
import com.firelion.crystals.kyber.util.baseMulMontgomery
import com.firelion.crystals.kyber.util.toIntUnsigned

internal class PolynomialVector(val polynomials: Array<Polynomial>) {
    constructor(params: KyberParams) : this(Array(params.KYBER_K) { Polynomial() })


    /**
     * Compress and serialize this vector of polynomials.
     */
    fun compress(out: ByteArray, offset: Int, params: KyberParams) {
        var outOffset = offset

        when (params.KYBER_POLYNOMIAL_VECTOR_COMPRESSED_BYTES) {
            params.KYBER_K * 352 -> {
                val t = IntArray(8)
                polynomials.forEach { poly ->
                    (0 until KYBER_N / 8).forEach { j ->
                        (0 until 8).forEach { k ->
                            t[k] = poly.coefficients[8 * j + k]
                            t[k] += (t[k] shr 15) and KYBER_Q
                            t[k] = (((t[k] shl 11) + KYBER_Q / 2) / KYBER_Q) and 0x7ff
                        }

                        out[outOffset++] = ((t[0] ushr 0).toByte())
                        out[outOffset++] = ((t[0] ushr 8) or (t[1] shl 3)).toByte()
                        out[outOffset++] = ((t[1] ushr 5) or (t[2] shl 6)).toByte()
                        out[outOffset++] = ((t[2] ushr 2).toByte())
                        out[outOffset++] = ((t[2] ushr 10) or (t[3] shl 1)).toByte()
                        out[outOffset++] = ((t[3] ushr 7) or (t[4] shl 4)).toByte()
                        out[outOffset++] = ((t[4] ushr 4) or (t[5] shl 7)).toByte()
                        out[outOffset++] = ((t[5] ushr 1).toByte())
                        out[outOffset++] = ((t[5] ushr 9) or (t[6] shl 2)).toByte()
                        out[outOffset++] = ((t[6] ushr 6) or (t[7] shl 5)).toByte()
                        out[outOffset++] = ((t[7] ushr 3).toByte())
                    }
                }
            }
            params.KYBER_K * 320 -> {
                val t = IntArray(4)
                polynomials.forEach { poly ->
                    (0 until KYBER_N / 4).forEach { j ->
                        (0 until 4).forEach { k ->
                            t[k] = poly.coefficients[4 * j + k]
                            t[k] += (t[k] shr 15) and KYBER_Q
                            t[k] = (((t[k] shl 10) + KYBER_Q / 2) / KYBER_Q) and 0x3ff
                        }

                        out[outOffset++] = (t[0] ushr 0).toByte()
                        out[outOffset++] = ((t[0] ushr 8) or (t[1] shl 2)).toByte()
                        out[outOffset++] = ((t[1] ushr 6) or (t[2] shl 4)).toByte()
                        out[outOffset++] = ((t[2] ushr 4) or (t[3] shl 6)).toByte()
                        out[outOffset++] = (t[3] ushr 2).toByte()
                    }
                }
            }
            else -> throw AssertionError("illegal KYBER_POLYNOMIAL_VECTOR_COMPRESSED_BYTES value ${params.KYBER_POLYNOMIAL_VECTOR_COMPRESSED_BYTES}")
        }
    }

    /**
     * Serialize this vector of polynomials.
     */
    fun toBytes(out: ByteArray) {
        polynomials.forEachIndexed { i, it ->
            it.toBytes(out, i * KYBER_POLYNOMIAL_BYTES)
        }
    }

    fun ntt() {
        polynomials.forEach {
            it.ntt()
        }
    }

    /**
     * Apply inverse NTT to all elements of this vector of polynomials
     * and multiply by Montgomery factor 2^16.
     */
    fun inverseNttToMont() {
        polynomials.forEach {
            it.inverseNttToMont()
        }
    }

    /**
     * Multiply elements of this and [right] in NTT domain, accumulate into [out],
     * and multiply by 2^(-16).
     */
    fun baseMulAccumulatedMontgomery(right: PolynomialVector, out: Polynomial) {
        out.coefficients.fill(0)

        val t = Polynomial()
        this.polynomials.indices.forEach {
            baseMulMontgomery(this.polynomials[it], right.polynomials[it], t)
            out.add(t, out)
        }

        out.reduce()
    }

    /**
     * Applies Barrett reduction to each coefficient
     * of each element of this vector of polynomials.
     */
    fun reduce() {
        polynomials.forEach {
            it.reduce()
        }
    }

    fun add(right: PolynomialVector, out: PolynomialVector) {
        out.polynomials.indices.forEach {
            this.polynomials[it].add(right.polynomials[it], out.polynomials[it])
        }
    }

    companion object {

        /**
         * De-serialize vector of polynomials. Inverse of [toBytes].
         */
        fun fromBytes(bytes: ByteArray, offset: Int, out: PolynomialVector) {
            out.polynomials.forEachIndexed { i, it ->
                Polynomial.fromBytes(bytes, offset + i * KYBER_POLYNOMIAL_BYTES, it)
            }
        }

        /**
         * De-serialize and decompress vector of polynomials.
         * Approximate inverse of [compress].
         */
        fun decompress(bytes: ByteArray, offset: Int, out: PolynomialVector, params: KyberParams) {
            when (params.KYBER_POLYNOMIAL_VECTOR_COMPRESSED_BYTES) {
                params.KYBER_K * 352 -> {
                    val t = IntArray(8)
                    var bytesOffset = offset

                    (0 until params.KYBER_K).forEach { i ->
                        (0 until KYBER_N / 8).forEach { j ->
                            t[0] =
                                (bytes[bytesOffset++].toIntUnsigned() ushr 0) or (bytes[bytesOffset].toIntUnsigned() shl 8)
                            t[1] =
                                (bytes[bytesOffset++].toIntUnsigned() ushr 3) or (bytes[bytesOffset].toIntUnsigned() shl 5)
                            t[2] =
                                (bytes[bytesOffset++].toIntUnsigned() ushr 6) or (bytes[bytesOffset++].toIntUnsigned() shl 2) or (bytes[bytesOffset].toIntUnsigned() shl 10)
                            t[3] =
                                (bytes[bytesOffset++].toIntUnsigned() ushr 1) or (bytes[bytesOffset].toIntUnsigned() shl 7)
                            t[4] =
                                (bytes[bytesOffset++].toIntUnsigned() ushr 4) or (bytes[bytesOffset].toIntUnsigned() shl 4)
                            t[5] =
                                (bytes[bytesOffset++].toIntUnsigned() ushr 7) or (bytes[bytesOffset++].toIntUnsigned() shl 1) or (bytes[bytesOffset].toIntUnsigned() shl 9)
                            t[6] =
                                (bytes[bytesOffset++].toIntUnsigned() ushr 2) or (bytes[bytesOffset].toIntUnsigned() shl 6)
                            t[7] =
                                (bytes[bytesOffset++].toIntUnsigned() ushr 5) or (bytes[bytesOffset].toIntUnsigned() shl 3)
                            bytesOffset++

                            (0 until 8).forEach { k ->
                                out.polynomials[i].coefficients[8 * j + k] = ((t[k] and 0x7ff) * KYBER_Q + 1024) ushr 11
                            }
                        }
                    }
                }
                params.KYBER_K * 320 -> {
                    val t = IntArray(4)
                    var bytesOffset = offset

                    (0 until params.KYBER_K).forEach { i ->
                        (0 until KYBER_N / 4).forEach { j ->

                            t[0] =
                                (bytes[bytesOffset++].toIntUnsigned() ushr 0) or (bytes[bytesOffset].toIntUnsigned() shl 8)
                            t[1] =
                                (bytes[bytesOffset++].toIntUnsigned() ushr 2) or (bytes[bytesOffset].toIntUnsigned() shl 6)
                            t[2] =
                                (bytes[bytesOffset++].toIntUnsigned() ushr 4) or (bytes[bytesOffset].toIntUnsigned() shl 4)
                            t[3] =
                                (bytes[bytesOffset++].toIntUnsigned() ushr 6) or (bytes[bytesOffset].toIntUnsigned() shl 2)
                            bytesOffset++

                            (0 until 4).forEach { k ->
                                out.polynomials[i].coefficients[4 * j + k] = ((t[k] and 0x3ff) * KYBER_Q + 512) ushr 10
                            }
                        }
                    }
                }
                else -> throw AssertionError("illegal KYBER_POLYNOMIAL_VECTOR_COMPRESSED_BYTES value ${params.KYBER_POLYNOMIAL_VECTOR_COMPRESSED_BYTES}")
            }
        }
    }
}