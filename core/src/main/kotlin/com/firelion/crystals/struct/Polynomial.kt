package com.firelion.crystals.struct

import com.firelion.crystals.util.*
import com.firelion.crystals.util.KyberParams.Companion.KYBER_ETA2
import com.firelion.crystals.util.KyberParams.Companion.KYBER_INDCPA_MESSAGE_BYTES
import com.firelion.crystals.util.KyberParams.Companion.KYBER_N
import com.firelion.crystals.util.KyberParams.Companion.KYBER_Q
import kotlin.experimental.and
import kotlin.experimental.or

internal class Polynomial(val coefficients: IntArray) {
    constructor(size: Int = KYBER_N) : this(IntArray(size))

    fun compress(output: ByteArray, offset: Int, params: KyberParams) {
        var outputOffset = offset
        val t = ByteArray(8)

        when (params.KYBER_POLYNOMIAL_COMPRESSED_BYTES) {
            128 -> {
                (0 until KYBER_N / 8).forEach { i ->
                    (0 until 8).forEach { j ->
                        // map to positive standard representatives
                        var u = coefficients[8 * i + j]
                        u += (u shr 15) and KYBER_Q
                        t[j] = ((((u shl 4) + KYBER_Q / 2) / KYBER_Q) and 15).toByte()
                    }

                    output[outputOffset++] = t[0] or (t[1] shl 4)
                    output[outputOffset++] = t[2] or (t[3] shl 4)
                    output[outputOffset++] = t[4] or (t[5] shl 4)
                    output[outputOffset++] = t[6] or (t[7] shl 4)
                }
            }
            160 -> {
                (0 until KYBER_N / 8).forEach { i ->
                    (0 until 8).forEach { j ->
                        // map to positive standard representatives
                        var u = coefficients[8 * i + j]
                        u += (u shr 15) and KYBER_Q
                        t[j] = ((((u shl 5) + KYBER_Q / 2) / KYBER_Q) and 31).toByte()
                    }

                    output[outputOffset++] = (t[0] ushr 0) or (t[1] shl 5)
                    output[outputOffset++] = (t[1] ushr 3) or (t[2] shl 2) or (t[3] shl 7)
                    output[outputOffset++] = (t[3] ushr 1) or (t[4] shl 4)
                    output[outputOffset++] = (t[4] ushr 4) or (t[5] shl 1) or (t[6] shl 6)
                    output[outputOffset++] = (t[6] ushr 2) or (t[7] shl 3)
                }
            }
            else -> throw AssertionError("illegal KYBER_POLYNOMIAL_COMPRESSED_BYTES value ${params.KYBER_POLYNOMIAL_COMPRESSED_BYTES}")
        }
    }

    fun toBytes(output: ByteArray, offset: Int) {
        (0 until KYBER_N / 2).forEach { i ->
            // map to positive standard representatives
            var t0 = coefficients[2 * i]
            t0 += (t0 shr 15) and KYBER_Q
            var t1 = coefficients[2 * i + 1]
            t1 += (t1 shr 15) and KYBER_Q

            output[offset + 3 * i + 0] = (t0 ushr 0).toByte()
            output[offset + 3 * i + 1] = ((t0 ushr 8) or (t1 shl 4)).toByte()
            output[offset + 3 * i + 2] = (t1 ushr 4).toByte()
        }
    }

    /**
     * Convert this polynomial to 32-byte message.
     */
    fun toMsg(out: ByteArray, outOffset: Int) {
        (0 until KYBER_N / 8).forEach { i ->
            out[outOffset + i] = 0
            (0 until 8).forEach { j ->
                var t = coefficients[8 * i + j]
                t += (t ushr 15) and KYBER_Q
                t = (((t shl 1) + KYBER_Q / 2) / KYBER_Q) and 1
                out[outOffset + i] = out[outOffset + i] or (t shl j).toByte()
            }
        }
    }

    fun ntt() {
        coefficients.ntt()
        reduce()
    }

    fun inverseNttToMont() {
        coefficients.inverseNtt()
    }

    /**
     * In-place conversion of all coefficients of this polynomial
     * from normal domain to Montgomery domain.
     */
    fun toMont() {
        val f = ((1L shl 32) % KYBER_Q).toInt()

        coefficients.reinitialize {
            (coefficients[it] * f).montgomeryReduce()
        }
    }

    /**
     * Applies Barrett reduction to all coefficients of this polynomial.
     */
    fun reduce() {
        coefficients.reinitialize {
            coefficients[it].barrettReduce()
        }
    }

    fun add(right: Polynomial, out: Polynomial) {
        out.coefficients.reinitialize {
            coefficients[it] + right.coefficients[it]
        }
    }

    fun sub(right: Polynomial, out: Polynomial) {
        out.coefficients.reinitialize {
            coefficients[it] - right.coefficients[it]
        }
    }


    companion object {
        fun decompress(bytes: ByteArray, offset: Int, out: Polynomial, params: KyberParams) {
            when (params.KYBER_POLYNOMIAL_COMPRESSED_BYTES) {
                128 -> {
                    (0 until KYBER_N / 2).forEach { i ->
                        out.coefficients[2 * i + 0] = (((bytes[offset + i] and 15) * KYBER_Q) + 8) ushr 4
                        out.coefficients[2 * i + 1] = (((bytes[offset + i] ushr 4) * KYBER_Q) + 8) ushr 4
                    }
                }
                160 -> {
                    val t = ByteArray(8)
                    (0 until KYBER_N / 8).forEach { i ->
                        t[0] = (bytes[offset + i * 5] ushr 0)
                        t[1] = (bytes[offset + i * 5] ushr 5) or (bytes[offset + i * 5 + 1] shl 3)
                        t[2] = (bytes[offset + i * 5 + 1] ushr 2)
                        t[3] = (bytes[offset + i * 5 + 1] ushr 7) or (bytes[offset + i * 5 + 2] shl 1)
                        t[4] = (bytes[offset + i * 5 + 2] ushr 4) or (bytes[offset + i * 5 + 3] shl 4)
                        t[5] = (bytes[offset + i * 5 + 3] ushr 1)
                        t[6] = (bytes[offset + i * 5 + 3] ushr 6) or (bytes[offset + i * 5 + 4] shl 2)
                        t[7] = (bytes[offset + i * 5 + 4] ushr 3)

                        (0 until 8).forEach { j ->
                            out.coefficients[8 * i + j] = ((t[j] and 31) * KYBER_Q + 16) shr 5
                        }
                    }
                }

                else -> throw AssertionError("illegal KYBER_POLYNOMIAL_COMPRESSED_BYTES value ${params.KYBER_POLYNOMIAL_COMPRESSED_BYTES}")
            }
        }

        /**
         * De-serialization of a polynomial. Inverse of [toBytes].
         */
        fun fromBytes(bytes: ByteArray, offset: Int, out: Polynomial) {
            (0 until KYBER_N / 2).forEach { i ->
                out.coefficients[2 * i] =
                    ((bytes[offset + 3 * i + 0].toIntUnsigned() shr 0) or (bytes[offset + 3 * i + 1].toIntUnsigned() shl 8)) and 0xfff
                out.coefficients[2 * i + 1] =
                    ((bytes[offset + 3 * i + 1].toIntUnsigned() shr 4) or (bytes[offset + 3 * i + 2].toIntUnsigned() shl 4)) and 0xfff
            }
        }

        /**
         * Convert 32-byte message to polynomial.
         */
        fun fromMsg(msg: ByteArray, out: Polynomial) {
            var mask: Int

            if (KYBER_INDCPA_MESSAGE_BYTES != KYBER_N / 8)
                throw AssertionError("KYBER_INDCPA_MESSAGE_BYTES must be equal to KYBER_N / 8 bytes")

            (0 until KYBER_N / 8).forEach { i ->
                (0 until 8).forEach { j ->
                    mask = -((msg[i] ushr j) and 1)
                    out.coefficients[8 * i + j] = mask and (KYBER_Q + 1) / 2
                }
            }
        }

        /**
         * Sample a polynomial deterministically from a seed and a nonce,
         * with output polynomial close to centered binomial distribution
         * with parameter KYBER_ETA1.
         */
        fun getNoiseEta1(seed: ByteArray, seedOffset: Int, nonce: Byte, out: Polynomial, params: KyberParams) {
            val buf = ByteArray(params.KYBER_ETA1 * KYBER_N / 4)
            params.prf(buf, 0, buf.size, seed, seedOffset, nonce)
            cbdEta1(buf, out, params)
        }

        /**
         * Sample a polynomial deterministically from a seed and a nonce,
         * with output polynomial close to centered binomial distribution
         * with parameter KYBER_ETA2.
         */
        fun getNoiseEta2(seed: ByteArray, seedOffset: Int, nonce: Byte, out: Polynomial, params: KyberParams) {
            val buf = ByteArray(KYBER_ETA2 * KYBER_N / 4)
            params.prf(buf, 0, buf.size, seed, seedOffset, nonce)
            cbdEta2(buf, out)
        }
    }
}
