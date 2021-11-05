package com.firelion.crystals.dilithium.struct

import com.firelion.crystals.dilithium.util.DilithiumParams
import com.firelion.crystals.dilithium.util.toIntUnsigned

internal class PolynomialVector(val polynomials: Array<Polynomial>) {
    inline val size get() = polynomials.size

    constructor(size: Int) : this(Array(size) { Polynomial() })

    fun deepCopy(): PolynomialVector =
        PolynomialVector(Array(polynomials.size) { polynomials[it].deepCopy() })

    fun matrixPointwiseMontgomery(
        mat: Array<PolynomialVector>,
        v: PolynomialVector
    ) {
        polynomials.forEachIndexed { idx, it ->
            pointwiseAccumulatedMontgomery(it, mat[idx], v)
        }
    }

    fun uniformEta(seed: ByteArrayView, nonce: Short, params: DilithiumParams) {
        var n = nonce
        polynomials.forEach {
            it.uniformEta(seed, n++, params)
        }
    }

    fun uniformGamma1(seed: ByteArrayView, nonce: Short, params: DilithiumParams) {
        var n = (params.L * nonce.toIntUnsigned()).toShort()
        polynomials.forEach {
            it.uniformGamma1(seed, n++, params)
        }
    }

    fun reduce() {
        polynomials.forEach {
            it.reduce()
        }
    }


    fun pointwisePolynomialMontgomery(
        a: Polynomial,
        v: PolynomialVector
    ) {
        polynomials.forEachIndexed { idx, poly ->
            poly.pointwiseMontgomery(a, v.polynomials[idx])
        }
    }

    /**
     * Checks infinity norm of polynomials in vector.
     * This [PolynomialVector] should be reduced by [PolynomialVector.reduce].
     *
     * Returns `false` if norm of all polynomials is strictly smaller than [bound] <= (Q-1)/8
     * and `true` otherwise.
     **/
    fun checkNorm(bound: Int): Boolean {
        polynomials.forEach {
            if (it.checkNorm(bound)) return true
        }
        return false
    }

    /**
     * Adds Q to all negative coefficients.
     **/
    fun caddq() {
        polynomials.forEach {
            it.caddq()
        }
    }

    /**
     * Multiply vector of polynomials by `2^D` without modular reduction.
     * This [PolynomialVector] coefficients should be less than `2^{31-D}`.
     **/
    fun shiftLeft() {
        polynomials.forEach {
            it.shiftLeft()
        }
    }

    /**
     * Computes a0, a1 such that `a mod^+ Q = a1*2^D + a0` with `-2^{D-1} < a0 <= 2^{D-1}`.
     *
     * Coefficients should be standard representatives.
     **/
    fun power2Round(v0: PolynomialVector, v: PolynomialVector) {
        polynomials.indices.forEach {
            polynomials[it].power2Round(v0.polynomials[it], v.polynomials[it])
        }
    }

    /**
     * Compute high and low bits a0, a1 such a `mod^+ Q = a1*ALPHA + a0`
     * with `-ALPHA/2 < a0 <= ALPHA/2` except `a1 = (Q-1)/ALPHA`
     * where we set `a1 = 0` and `-ALPHA/2 <= a0 = a mod Q - Q < 0`.
     *
     * Coefficients should be standard representatives.
     **/
    fun decompose(v0: PolynomialVector, v: PolynomialVector, params: DilithiumParams) {
        polynomials.indices.forEach {
            polynomials[it].decompose(v0.polynomials[it], v.polynomials[it], params)
        }
    }

    /**
     * Computes hint vector.
     *
     * Returns number of `1` bits.
     **/
    fun makeHint(v0: PolynomialVector, v1: PolynomialVector, params: DilithiumParams): /*U*/Int {
        var s = 0
        polynomials.indices.forEach {
            s += polynomials[it].makeHint(v0.polynomials[it], v1.polynomials[it], params)
        }
        return s
    }

    /**
     * Uses hint vector to correct the high bits of [u].
     **/
    fun useHint(u: PolynomialVector, h: PolynomialVector, params: DilithiumParams) {
        polynomials.indices.forEach {
            polynomials[it].useHint(u.polynomials[it], h.polynomials[it], params)
        }
    }

    fun packW1(r: ByteArrayView, params: DilithiumParams) {
        val offset = r.offset

        polynomials.forEach {
            it.packW1(r, params)
            r += params.POLYNOMIAL_W1_PACKED_BYTES
        }

        r.offset = offset
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

    fun add(right: PolynomialVector, out: PolynomialVector) {
        out.polynomials.indices.forEach {
            this.polynomials[it].add(right.polynomials[it], out.polynomials[it])
        }
    }

    fun sub(right: PolynomialVector, out: PolynomialVector) {
        out.polynomials.indices.forEach {
            this.polynomials[it].sub(right.polynomials[it], out.polynomials[it])
        }
    }

    companion object {

        /**
         * Implementation of ExpandA.
         *
         * Generates matrix A with uniformly random coefficients `a_{i,j}`
         * by performing rejection sampling on the output stream of SHAKE128(rho|j|i).
         **/
        fun expandMatrix(
            mat: Array<PolynomialVector>,
            rho: ByteArrayView,
            params: DilithiumParams
        ) {
            mat.forEachIndexed { vecIdx, vec ->
                vec.polynomials.forEachIndexed { polyIdx, poly ->
                    poly.uniform(rho, ((vecIdx shl 8 /* vecIdx * 256 */) + polyIdx).toShort(), params)
                }
            }
        }

        /**
         * Pointwise multiply vectors of polynomials,
         * multiply resulting vector by `2^{-32}`
         * and add (accumulate) polynomials in it.
         *
         * Input/output polynomials should/will be in NTT domain representation.
         *
         * [u] and [v] are input [PolynomialVector]s and [w] is output [Polynomial].
         **/
        fun pointwiseAccumulatedMontgomery(
            w: Polynomial,
            u: PolynomialVector,
            v: PolynomialVector
        ) {
            val t = Polynomial()

            w.pointwiseMontgomery(u.polynomials[0], v.polynomials[0])
            (1 until v.size).forEach {
                t.pointwiseMontgomery(u.polynomials[it], v.polynomials[it])
                w.add(t, w)
            }
        }
    }
}