package com.firelion.crystals.dilithium.struct

import com.firelion.crystals.dilithium.digest.SHAKE256_RATE
import com.firelion.crystals.dilithium.util.*
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.D
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.DILITHIUM_Q
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.N
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.SEED_BYTES
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.STREAM128_BLOCK_BYTES
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.STREAM256_BLOCK_BYTES
import kotlin.experimental.and

internal class Polynomial(val coefficients: IntArray) {
    constructor(size: Int = N) : this(IntArray(size))

    fun deepCopy(): Polynomial =
        Polynomial(coefficients.copyOf())

    /**
     * Reduces all coefficients of polynomial to representative in [-6283009,6283007].
     **/
    fun reduce() {
        coefficients.mapInPlace(::reduce32)
    }

    /**
     * Adds Q to all negative coefficients.
     **/
    fun caddq() {
        coefficients.mapInPlace {
            caddq(it)
        }
    }

    /**
     * Multiplies polynomial by 2^D without modular reduction.
     * Assumes input coefficients to be less than 2^{31-D} in absolute value.
     *
     **/
    fun shiftLeft() {
        coefficients.mapInPlace {
            it shl D
        }
    }

    /**
     * Applies NTT to the polynomial.
     */
    fun ntt() {
        coefficients.ntt()
    }

    /**
     *  Multiplies polynomials in NTT domain representation and multiples it by 2^{-32}.
     **/
    fun pointwiseMontgomery(a: Polynomial, b: Polynomial) {
        coefficients.indices.forEach {
            coefficients[it] = (a.coefficients[it].toLong() * b.coefficients[it]).montgomeryReduce()
        }
    }

    /**
     * Computes c0, c1 such that c mod Q = c1*2^D + c0  with -2^{D-1} < c0 <= 2^{D-1}
     * for each coefficient `c` of this Polynomial and writes c0's to [a0] and c1's to [a].
     *
     * Coefficients should be standard representatives.
     **/
    fun power2Round(a0: Polynomial, a: Polynomial) {
        coefficients.indices.forEach {
            val (r0, r1) = power2Round(a.coefficients[it])
            a0.coefficients[it] = r0
            coefficients[it] = r1
        }
    }

    /**
     * Computes high and low bits c0, c1 such c mod Q = c1*ALPHA + c0 with
     * `-ALPHA/2 < c0 <= ALPHA/2` except `c1 = (Q-1)/ALPHA` where we set
     * `c1 = 0` and `-ALPHA/2 <= c0 = c mod Q - Q < 0` for all coefficients.
     *
     * Coefficients should be standard representatives.
     **/
    fun decompose(a0: Polynomial, a: Polynomial, params: DilithiumParams) {
        coefficients.indices.forEach {
            val (r0, r1) = decompose(a.coefficients[it], params)
            a0.coefficients[it] = r0
            coefficients[it] = r1
        }
    }

    /**
     * Computes hint polynomial.
     *
     * The coefficients of which indicate whether the low bits of the corresponding
     * coefficient of the input polynomial overflow into the high bits.
     *
     * [a0] - input polynomial lower part
     * [a1] - input polynomial higher part
     *
     * Returns number of `1` bits.
     **/
    fun makeHint(a0: Polynomial, a1: Polynomial, params: DilithiumParams): /*U*/Int {
        var s = 0

        coefficients.indices.forEach {
            coefficients[it] =
                if (makeHint(a0.coefficients[it], a1.coefficients[it], params)) 1 else 0
            s += coefficients[it]
        }

        return s
    }

    /**
     * Uses hint polynomial to correct the high bits of [a] polynomial.
     **/
    fun useHint(a: Polynomial, h: Polynomial, params: DilithiumParams) {
        coefficients.indices.forEach {
            coefficients[it] =
                useHint(a.coefficients[it], h.coefficients[it] != 0, params)
        }
    }

    /**
     * Checks infinity norm of polynomial against given bound.
     * Assumes input coefficients were reduced by [reduce32].
     *
     * [b] is norm bound.
     *
     * Returns `false` if norm is strictly smaller than b <= (Q-1)/8 and `true` otherwise.
     **/
    fun checkNorm(b: Int): Boolean {
        var t: Int

        if (b > (DILITHIUM_Q - 1) / 8)
            return true

        coefficients.forEach {
            t = it shr 31
            t = it - (t and (2 * it))

            if (t >= b) return true
        }

        return false
    }

    /**
     * Sample polynomial with uniformly random coefficients in `[0,Q-1]`
     * by performing rejection sampling on the output stream of SHAKE256(seed|nonce).
     **/
    fun uniform(
        seed: ByteArrayView,
        nonce: Short,
        params: DilithiumParams
    ) {
        val coefficients = IntArrayView(coefficients)

        var bufferLength = POLYNOMIAL_UNIFORM_BLOCKS_COUNT * STREAM128_BLOCK_BYTES
        val buffer = ByteArrayView(POLYNOMIAL_UNIFORM_BLOCKS_COUNT * STREAM128_BLOCK_BYTES + 2)

        with(params.STREAM128) {
            init(seed, nonce)
            squeezeBlocks(buffer, POLYNOMIAL_UNIFORM_BLOCKS_COUNT)
        }
        coefficients.offset = uniformRejection(coefficients, N, buffer, bufferLength)

        while (coefficients.offset < N) {
            val off = bufferLength % 3
            System.arraycopy(buffer.array, bufferLength - off, buffer.array, 0, off)

            buffer.offset += off
            params.STREAM128.squeezeBlocks(buffer, 1)
            buffer.offset = 0

            bufferLength = STREAM128_BLOCK_BYTES + off
            coefficients.offset += uniformRejection(coefficients, N - coefficients.offset, buffer, bufferLength)
        }
    }

    /**
     * Sample polynomial with uniformly random coefficients in `[-[DilithiumParams.ETA],[DilithiumParams.ETA]]`
     * by performing rejection sampling on the output stream from SHAKE256(seed|nonce).
     **/

    fun uniformEta(
        seed: ByteArrayView,
        nonce: Short,
        params: DilithiumParams
    ) {
        val POLY_UNIFORM_ETA_BLOCK_COUNT = when (params.ETA) {
            2 -> ((136 + STREAM256_BLOCK_BYTES - 1) / STREAM256_BLOCK_BYTES)
            4 -> ((227 + STREAM256_BLOCK_BYTES - 1) / STREAM256_BLOCK_BYTES)
            else -> throw AssertionError("illegal ETA value ${params.ETA}")
        }

        val coefficients = IntArrayView(coefficients)

        val bufferLength = POLY_UNIFORM_ETA_BLOCK_COUNT * STREAM256_BLOCK_BYTES
        val buffer = ByteArrayView(bufferLength)

        with(params.STREAM256) {
            init(seed, nonce)
            squeezeBlocks(buffer, POLY_UNIFORM_ETA_BLOCK_COUNT)
        }

        coefficients.offset = etaRejection(coefficients, N, buffer, bufferLength, params)

        while (coefficients.offset < N) {
            params.STREAM256.squeezeBlocks(buffer, 1)
            coefficients.offset += etaRejection(
                coefficients,
                N - coefficients.offset,
                buffer,
                STREAM256_BLOCK_BYTES,
                params
            )
        }
    }

    /**
     * Sample polynomial with uniformly random coefficients
     * in `[-([DilithiumParams.GAMMA1] - 1), [DilithiumParams.GAMMA1]]`
     * by unpacking output stream  of SHAKE256(seed|nonce).
     **/
    fun uniformGamma1(
        seed: ByteArrayView,
        nonce: Short,
        params: DilithiumParams
    ) {
        val POLY_UNIFORM_GAMMA1_BLOCK_COUNT =
            ((params.POLYNOMIAL_Z_PACKED_BYTES + STREAM256_BLOCK_BYTES - 1) / STREAM256_BLOCK_BYTES)

        val buffer = ByteArrayView(POLY_UNIFORM_GAMMA1_BLOCK_COUNT * STREAM256_BLOCK_BYTES)

        with(params.STREAM256) {
            init(seed, nonce)
            squeezeBlocks(buffer, POLY_UNIFORM_GAMMA1_BLOCK_COUNT)
        }
        unpackZ(buffer, params)
    }

    /**
     * Implementation of `H`. Samples polynomial with [DilithiumParams.TAU] nonzero coefficients
     * in `{-1,1}`  using the output stream of SHAKE256(seed).
     **/
    fun challenge(seed: ByteArrayView, params: DilithiumParams) {
        val buffer = ByteArrayView(SHAKE256_RATE)

        with(params.SHAKE256) {
            absorb(seed, SEED_BYTES)
            squeezeBlocks(buffer, 1)
        }

        var signs = 0L
        (0 until 8).forEach {
            signs = signs or (buffer[it].toLongUnsigned() shl (it * 8))
        }

        buffer.offset = 8

        coefficients.fill(0)

        (N - params.TAU until N).forEach {
            var b: Int
            do {
                if (buffer.offset >= buffer.array.size) {
                    buffer.offset = 0
                    params.SHAKE256.squeezeBlocks(buffer, 1)
                }
                b = buffer[0].toIntUnsigned()
                buffer.offset++

            } while (b > it)

            coefficients[it] = coefficients[b]
            coefficients[b] = 1 - 2 * (signs and 1).toInt()
            signs = signs ushr 1
        }

        params.SHAKE256.reset()
    }

    /**
     * Pack polynomial with coefficients in `[-[DilithiumParams.ETA],[DilithiumParams.ETA]]`.
     **/
    fun packEta(r: ByteArrayView, params: DilithiumParams) {
        val t = ByteArray(8)

        when (params.ETA) {
            2 -> {
                (coefficients.indices step 8).forEach {
                    t[0] = (2 - coefficients[it + 0]).toByte()
                    t[1] = (2 - coefficients[it + 1]).toByte()
                    t[2] = (2 - coefficients[it + 2]).toByte()
                    t[3] = (2 - coefficients[it + 3]).toByte()
                    t[4] = (2 - coefficients[it + 4]).toByte()
                    t[5] = (2 - coefficients[it + 5]).toByte()
                    t[6] = (2 - coefficients[it + 6]).toByte()
                    t[7] = (2 - coefficients[it + 7]).toByte()

                    val i = (it shr 3) * 3 /* it / 8 * 3 */

                    r[i + 0] = (t[0] ushr 0) or (t[1] shl 3) or (t[2] shl 6)
                    r[i + 1] = (t[2] ushr 2) or (t[3] shl 1) or (t[4] shl 4) or (t[5] shl 7)
                    r[i + 2] = (t[5] ushr 1) or (t[6] shl 2) or (t[7] shl 5)
                }
            }
            4 -> {
                (coefficients.indices step 2).forEach {

                    t[0] = (4 - coefficients[it + 0]).toByte()
                    t[1] = (4 - coefficients[it + 1]).toByte()
                    r[it shr 1 /* it / 2 */] = t[0] or (t[1] shl 4)
                }

            }
            else -> throw AssertionError("illegal ETA value ${params.ETA}")
        }
    }

    /**
     * Unpacks polynomial with coefficients in `[-[DilithiumParams.ETA],[DilithiumParams.ETA]]`.
     **/
    fun unpackEta(a: ByteArrayView, params: DilithiumParams) {
        when (params.ETA) {
            2 -> {
                (coefficients.indices step 8).forEach {
                    val i = (it shr 3) * 3 /* it / 8 * 3 */

                    coefficients[it + 0] = ((a[i + 0] ushr 0) and 7).toInt()
                    coefficients[it + 1] = ((a[i + 0] ushr 3) and 7).toInt()
                    coefficients[it + 2] = (((a[i + 0] ushr 6) or (a[i + 1] shl 2)) and 7).toInt()
                    coefficients[it + 3] = ((a[i + 1] ushr 1) and 7).toInt()
                    coefficients[it + 4] = ((a[i + 1] ushr 4) and 7).toInt()
                    coefficients[it + 5] = (((a[i + 1] ushr 7) or (a[i + 2] shl 1)) and 7).toInt()
                    coefficients[it + 6] = ((a[i + 2] ushr 2) and 7).toInt()
                    coefficients[it + 7] = ((a[i + 2] ushr 5) and 7).toInt()

                    coefficients[it + 0] = 2 - coefficients[it + 0]
                    coefficients[it + 1] = 2 - coefficients[it + 1]
                    coefficients[it + 2] = 2 - coefficients[it + 2]
                    coefficients[it + 3] = 2 - coefficients[it + 3]
                    coefficients[it + 4] = 2 - coefficients[it + 4]
                    coefficients[it + 5] = 2 - coefficients[it + 5]
                    coefficients[it + 6] = 2 - coefficients[it + 6]
                    coefficients[it + 7] = 2 - coefficients[it + 7]
                }
            }
            4 -> {
                (coefficients.indices step 2).forEach {
                    coefficients[it + 0] = (a[it shr 1 /* it / 2 */] and 0xf).toInt()
                    coefficients[it + 1] = (a[it shr 1 /* it / 2 */] ushr 4).toInt()
                    coefficients[it + 0] = 4 - coefficients[it + 0]
                    coefficients[it + 1] = 4 - coefficients[it + 1]
                }
            }
            else -> throw AssertionError("illegal ETA value ${params.ETA}")
        }
    }

    /**
     * Pack polynomial t0 with coefficients in `(-2^{D-1}, 2^{D-1}]`.
     **/
    fun packT0(r: ByteArrayView) {
        val t = IntArray(8)

        (coefficients.indices step 8).forEach {
            t[0] = (1 shl (D - 1)) - coefficients[it + 0]
            t[1] = (1 shl (D - 1)) - coefficients[it + 1]
            t[2] = (1 shl (D - 1)) - coefficients[it + 2]
            t[3] = (1 shl (D - 1)) - coefficients[it + 3]
            t[4] = (1 shl (D - 1)) - coefficients[it + 4]
            t[5] = (1 shl (D - 1)) - coefficients[it + 5]
            t[6] = (1 shl (D - 1)) - coefficients[it + 6]
            t[7] = (1 shl (D - 1)) - coefficients[it + 7]

            val i = (it shr 3) * 13 /* it / 8 * 13 */
            r[i + 0] = t[0].toByte()
            r[i + 1] = (t[0] ushr 8).toByte()
            r[i + 1] = r[i + 1] or ((t[1] shl 5).toByte())
            r[i + 2] = (t[1] ushr 3).toByte()
            r[i + 3] = (t[1] ushr 11).toByte()
            r[i + 3] = r[i + 3] or ((t[2] shl 2).toByte())
            r[i + 4] = (t[2] ushr 6).toByte()
            r[i + 4] = r[i + 4] or ((t[3] shl 7).toByte())
            r[i + 5] = (t[3] ushr 1).toByte()
            r[i + 6] = (t[3] ushr 9).toByte()
            r[i + 6] = r[i + 6] or ((t[4] shl 4).toByte())
            r[i + 7] = (t[4] ushr 4).toByte()
            r[i + 8] = (t[4] ushr 12).toByte()
            r[i + 8] = r[i + 8] or ((t[5] shl 1).toByte())
            r[i + 9] = (t[5] ushr 7).toByte()
            r[i + 9] = r[i + 9] or ((t[6] shl 6).toByte())
            r[i + 10] = (t[6] ushr 2).toByte()
            r[i + 11] = (t[6] ushr 10).toByte()
            r[i + 11] = r[i + 11] or ((t[7] shl 3).toByte())
            r[i + 12] = (t[7] ushr 5).toByte()
        }
    }

    /**
     * Unpacks polynomial t0 with coefficients in `(-2^{D-1}, 2^{D-1}]`.
     **/
    fun unpackT0(a: ByteArrayView) {
        (coefficients.indices step 8).forEach {
            val i = (it shr 3) * 13 /* it / 8 * 13 */
            coefficients[it + 0] = a[i + 0].toIntUnsigned()
            coefficients[it + 0] = coefficients[it + 0] or (a[i + 1].toIntUnsigned() shl 8)
            coefficients[it + 0] = coefficients[it + 0] and 0x1fff

            coefficients[it + 1] = (a[i + 1] ushr 5).toInt()
            coefficients[it + 1] = coefficients[it + 1] or (a[i + 2].toIntUnsigned() shl 3)
            coefficients[it + 1] = coefficients[it + 1] or (a[i + 3].toIntUnsigned() shl 11)
            coefficients[it + 1] = coefficients[it + 1] and 0x1fff

            coefficients[it + 2] = (a[i + 3] ushr 2).toInt()
            coefficients[it + 2] = coefficients[it + 2] or (a[i + 4].toIntUnsigned() shl 6)
            coefficients[it + 2] = coefficients[it + 2] and 0x1fff

            coefficients[it + 3] = (a[i + 4] ushr 7).toInt()
            coefficients[it + 3] = coefficients[it + 3] or (a[i + 5].toIntUnsigned() shl 1)
            coefficients[it + 3] = coefficients[it + 3] or (a[i + 6].toIntUnsigned() shl 9)
            coefficients[it + 3] = coefficients[it + 3] and 0x1fff

            coefficients[it + 4] = (a[i + 6] ushr 4).toInt()
            coefficients[it + 4] = coefficients[it + 4] or (a[i + 7].toIntUnsigned() shl 4)
            coefficients[it + 4] = coefficients[it + 4] or (a[i + 8].toIntUnsigned() shl 12)
            coefficients[it + 4] = coefficients[it + 4] and 0x1fff

            coefficients[it + 5] = (a[i + 8] ushr 1).toInt()
            coefficients[it + 5] = coefficients[it + 5] or (a[i + 9].toIntUnsigned() shl 7)
            coefficients[it + 5] = coefficients[it + 5] and 0x1fff

            coefficients[it + 6] = (a[i + 9] ushr 6).toInt()
            coefficients[it + 6] = coefficients[it + 6] or (a[i + 10].toIntUnsigned() shl 2)
            coefficients[it + 6] = coefficients[it + 6] or (a[i + 11].toIntUnsigned() shl 10)
            coefficients[it + 6] = coefficients[it + 6] and 0x1fff

            coefficients[it + 7] = (a[i + 11] ushr 3).toInt()
            coefficients[it + 7] = coefficients[it + 7] or (a[i + 12].toIntUnsigned() shl 5)
            coefficients[it + 7] = coefficients[it + 7] and 0x1fff

            coefficients[it + 0] = (1 shl (D - 1)) - coefficients[it + 0]
            coefficients[it + 1] = (1 shl (D - 1)) - coefficients[it + 1]
            coefficients[it + 2] = (1 shl (D - 1)) - coefficients[it + 2]
            coefficients[it + 3] = (1 shl (D - 1)) - coefficients[it + 3]
            coefficients[it + 4] = (1 shl (D - 1)) - coefficients[it + 4]
            coefficients[it + 5] = (1 shl (D - 1)) - coefficients[it + 5]
            coefficients[it + 6] = (1 shl (D - 1)) - coefficients[it + 6]
            coefficients[it + 7] = (1 shl (D - 1)) - coefficients[it + 7]
        }
    }

    /**
     * Pack polynomial t1 with coefficients fitting in 10 bits.
     *
     * Coefficients should be standard representatives.
     **/
    fun packT1(r: ByteArrayView) {
        (coefficients.indices step 4).forEach {
            val i = (it shr 2) * 5 /* it / 4 * 5 */
            r[i + 0] = ((coefficients[it + 0] ushr 0).toByte())
            r[i + 1] = ((coefficients[it + 0] ushr 8) or (coefficients[it + 1] shl 2)).toByte()
            r[i + 2] = ((coefficients[it + 1] ushr 6) or (coefficients[it + 2] shl 4)).toByte()
            r[i + 3] = ((coefficients[it + 2] ushr 4) or (coefficients[it + 3] shl 6)).toByte()
            r[i + 4] = (coefficients[it + 3] ushr 2).toByte()
        }
    }

    /**
     * Unpacks polynomial t1 with 10-bit coefficients.
     * Coefficients will be standard representatives.
     **/
    fun unpackT1(a: ByteArrayView) {
        (coefficients.indices step 4).forEach {
            val i = (it shr 2) * 5 /* it / 4 * 5 */
            coefficients[it + 0] =
                (((a[i + 0] ushr 0).toIntUnsigned() or (a[i + 1].toIntUnsigned() shl 8)) and 0x3ff)
            coefficients[it + 1] =
                (((a[i + 1] ushr 2).toIntUnsigned() or (a[i + 2].toIntUnsigned() shl 6)) and 0x3ff)
            coefficients[it + 2] =
                (((a[i + 2] ushr 4).toIntUnsigned() or (a[i + 3].toIntUnsigned() shl 4)) and 0x3ff)
            coefficients[it + 3] =
                (((a[i + 3] ushr 6).toIntUnsigned() or (a[i + 4].toIntUnsigned() shl 2)) and 0x3ff)
        }
    }

    /**
     * Pack polynomial with coefficients in `[-([DilithiumParams.GAMMA1] - 1), [DilithiumParams.GAMMA1]]`.
     **/
    fun packZ(r: ByteArrayView, params: DilithiumParams) {
        val t = IntArray(4)

        when (params.GAMMA1) {
            (1 shl 17) -> {
                (coefficients.indices step 4).forEach {
                    t[0] = params.GAMMA1 - coefficients[it + 0]
                    t[1] = params.GAMMA1 - coefficients[it + 1]
                    t[2] = params.GAMMA1 - coefficients[it + 2]
                    t[3] = params.GAMMA1 - coefficients[it + 3]

                    val i = (it shr 2) * 9 /* it / 8 * 9 */
                    r[i + 0] = t[0].toByte()
                    r[i + 1] = (t[0] ushr 8).toByte()
                    r[i + 2] = (t[0] ushr 16).toByte()
                    r[i + 2] = r[i + 2] or ((t[1] shl 2).toByte())
                    r[i + 3] = (t[1] ushr 6).toByte()
                    r[i + 4] = (t[1] ushr 14).toByte()
                    r[i + 4] = r[i + 4] or ((t[2] shl 4).toByte())
                    r[i + 5] = (t[2] ushr 4).toByte()
                    r[i + 6] = (t[2] ushr 12).toByte()
                    r[i + 6] = r[i + 6] or ((t[3] shl 6).toByte())
                    r[i + 7] = (t[3] ushr 2).toByte()
                    r[i + 8] = (t[3] ushr 10).toByte()
                }
            }
            (1 shl 19) -> {
                (coefficients.indices step 2).forEach {
                    t[0] = params.GAMMA1 - coefficients[it + 0]
                    t[1] = params.GAMMA1 - coefficients[it + 1]

                    val i = (it shr 1) * 5 /* i / 2 * 5 */
                    r[i + 0] = t[0].toByte()
                    r[i + 1] = (t[0] ushr 8).toByte()
                    r[i + 2] = (t[0] ushr 16).toByte()
                    r[i + 2] = r[i + 2] or ((t[1] shl 4).toByte())
                    r[i + 3] = (t[1] ushr 4).toByte()
                    r[i + 4] = (t[1] ushr 12).toByte()
                }
            }
            else -> throw AssertionError("illegal GAMMA1 value ${params.GAMMA1}")
        }
    }

    /**
     * Unpacks polynomial z with coefficients in `[-([DilithiumParams.GAMMA1] - 1), [DilithiumParams.GAMMA1]]`.
     **/
    fun unpackZ(a: ByteArrayView, params: DilithiumParams) {

        when (params.GAMMA1) {
            (1 shl 17) -> {
                (coefficients.indices step 4).forEach {
                    val i = (it shr 2) * 9 /* it / 4 * 9 */
                    coefficients[it + 0] = a[i + 0].toIntUnsigned()
                    coefficients[it + 0] = coefficients[it + 0] or (a[i + 1].toIntUnsigned() shl 8)
                    coefficients[it + 0] = coefficients[it + 0] or (a[i + 2].toIntUnsigned() shl 16)
                    coefficients[it + 0] = coefficients[it + 0] and (0x3ffff)

                    coefficients[it + 1] = (a[i + 2] ushr 2).toInt()
                    coefficients[it + 1] = coefficients[it + 1] or (a[i + 3].toIntUnsigned() shl 6)
                    coefficients[it + 1] = coefficients[it + 1] or (a[i + 4].toIntUnsigned() shl 14)
                    coefficients[it + 1] = coefficients[it + 1] and 0x3ffff

                    coefficients[it + 2] = (a[i + 4] ushr 4).toInt()
                    coefficients[it + 2] = coefficients[it + 2] or (a[i + 5].toIntUnsigned() shl 4)
                    coefficients[it + 2] = coefficients[it + 2] or (a[i + 6].toIntUnsigned() shl 12)
                    coefficients[it + 2] = coefficients[it + 2] and 0x3ffff

                    coefficients[it + 3] = (a[i + 6] ushr 6).toInt()
                    coefficients[it + 3] = coefficients[it + 3] or (a[i + 7].toIntUnsigned() shl 2)
                    coefficients[it + 3] = coefficients[it + 3] or (a[i + 8].toIntUnsigned() shl 10)
                    coefficients[it + 3] = coefficients[it + 3] and 0x3ffff

                    coefficients[it + 0] = params.GAMMA1 - coefficients[it + 0]
                    coefficients[it + 1] = params.GAMMA1 - coefficients[it + 1]
                    coefficients[it + 2] = params.GAMMA1 - coefficients[it + 2]
                    coefficients[it + 3] = params.GAMMA1 - coefficients[it + 3]
                }
            }
            (1 shl 19) -> {
                (coefficients.indices step 2).forEach {
                    val i = (it shr 1) * 5 /* it / 2 * 5 */

                    coefficients[it + 0] = a[i + 0].toIntUnsigned()
                    coefficients[it + 0] = coefficients[it + 0] or (a[i + 1].toIntUnsigned() shl 8)
                    coefficients[it + 0] = coefficients[it + 0] or (a[i + 2].toIntUnsigned() shl 16)
                    coefficients[it + 0] = coefficients[it + 0] and 0xfffff

                    coefficients[it + 1] = (a[i + 2] ushr 4).toInt()
                    coefficients[it + 1] = coefficients[it + 1] or (a[i + 3].toIntUnsigned() shl 4)
                    coefficients[it + 1] = coefficients[it + 1] or (a[i + 4].toIntUnsigned() shl 12)
                    coefficients[it + 0] = coefficients[it + 0] and 0xfffff

                    coefficients[it + 0] = params.GAMMA1 - coefficients[it + 0]
                    coefficients[it + 1] = params.GAMMA1 - coefficients[it + 1]
                }
            }
            else -> throw AssertionError("illegal GAMMA1 value ${params.GAMMA1}")
        }
    }

    /**
     * Packs polynomial w1 with coefficients in [0,15] or [0,43].
     *
     * Coefficients should be standard representatives.
     **/
    fun packW1(r: ByteArrayView, params: DilithiumParams) {
        when (params.GAMMA2) {
            (DILITHIUM_Q - 1) / 88 -> {
                (coefficients.indices step 4).forEach {
                    val i = (it shr 2) * 3 /* it / 4 * 3 */
                    r[i + 0] = coefficients[it + 0].toByte()
                    r[i + 0] = r[i + 0] or ((coefficients[it + 1] shl 6).toByte())
                    r[i + 1] = (coefficients[it + 1] ushr 2).toByte()
                    r[i + 1] = r[i + 1] or ((coefficients[it + 2] shl 4).toByte())
                    r[i + 2] = (coefficients[it + 2] ushr 4).toByte()
                    r[i + 2] = r[i + 2] or ((coefficients[it + 3] shl 2).toByte())

                }
            }

            (DILITHIUM_Q - 1) / 32 -> {
                (coefficients.indices step 2).forEach {
                    r[it shr 1 /* it / 2 */] = (coefficients[it + 0] or (coefficients[it + 1] shl 4)).toByte()
                }

            }

            else -> throw AssertionError("illegal GAMMA2 value ${params.GAMMA2}")
        }
    }

    fun inverseNttToMont() {
        coefficients.inverseNtt()
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

    private companion object {

        /**
         * Samples uniformly random coefficients in [0, Q-1]
         * by performing rejection sampling on array of random bytes.
         *
         * Returns number of sampled coefficients.
         * Can be smaller than len if not enough random bytes were given.
         **/
        fun uniformRejection(
            a: IntArrayView,
            len: Int,
            buffer: ByteArrayView,
            bufferLength: Int
        ): Int {
            var ctr = 0
            var pos = 0

            while (ctr < len && pos + 3 <= bufferLength) {
                val t = load24LittleEndian(buffer.array, pos + buffer.offset) and 0x7fffff
                pos += 3

                if (t < DILITHIUM_Q)
                    a[ctr++] = t
            }

            return ctr
        }


        /**
         * Sample uniformly random coefficients in [-[DilithiumParams.ETA], [DilithiumParams.ETA]]
         * by performing rejection sampling on array of random bytes.
         *
         * Returns number of sampled coefficients.
         * Can be smaller than len if not enough random bytes were given.
         **/
        fun etaRejection(
            a: IntArrayView,
            len: Int,
            buffer: ByteArrayView,
            bufferLength: Int,
            params: DilithiumParams
        ): /*U*/Int {
            var ctr = 0
            var pos = 0

            while (ctr < len && pos < bufferLength) {
                var t0 = (buffer[pos] and 0xf).toIntUnsigned()
                var t1 = (buffer[pos++] ushr 4).toIntUnsigned()

                when (params.ETA) {
                    2 -> {
                        if (t0 < 15) {
                            t0 -= ((205 * t0) ushr 10) * 5
                            a[ctr++] = 2 - t0
                        }

                        if (t1 < 15 && ctr < len) {
                            t1 -= ((205 * t1) ushr 10) * 5
                            a[ctr++] = 2 - t1
                        }
                    }
                    4 -> {
                        if (t0 < 9)
                            a[ctr++] = 4 - t0

                        if (t1 < 9 && ctr < len)
                            a[ctr++] = 4 - t1
                    }
                    else -> throw AssertionError("illegal ETA value ${params.ETA}")
                }
            }

            return ctr
        }

        private const val POLYNOMIAL_UNIFORM_BLOCKS_COUNT =
            ((768 + STREAM128_BLOCK_BYTES - 1) / STREAM128_BLOCK_BYTES)
    }
}
