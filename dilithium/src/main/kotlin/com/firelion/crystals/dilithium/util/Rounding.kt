package com.firelion.crystals.dilithium.util

import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.D
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.DILITHIUM_Q


/**
 * For finite field element a, computes a0, a1 such that
 *
 * ```(a mod^+ Q) = a1 * 2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}```
 *
 * Returns a pair of a0 and a1.
 */
internal fun power2Round(a: Int): Pair<Int, Int> {
    val a1 = (a + (1 shl (D - 1)) - 1) shr D
    val a0 = a - (a1 shl D)

    return a0 to a1;
}

/**
 * For finite field element a, computes high and low bits a0, a1 such that
 *
 * ```a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2```
 *
 * except if ```a1 = (Q-1)/ALPHA```
 *
 * where we set a1 = 0 and ```-ALPHA/2 <= a0 = a mod^+ Q - Q < 0```.
 *
 * Returns a pair of a0 and a1
 */
internal fun decompose(a: Int, params: DilithiumParams): Pair<Int, Int> {
    var a1 = (a + 127) shr 7
    when (params.GAMMA2) {
        (DILITHIUM_Q - 1) / 32 -> {
            a1 = (a1 * 1025 + (1 shl 21)) shr 22
            a1 = a1 and 0xf
        }
        (DILITHIUM_Q - 1) / 88 -> {
            a1 = (a1 * 11275 + (1 shl 23)) shr 24
            a1 = a1 xor (((43 - a1) shr 31) and a1)
        }
    }
    var a0 = a - a1 * 2 * params.GAMMA2
    a0 -= (((DILITHIUM_Q - 1) / 2 - a0) shr 31) and DILITHIUM_Q

    return a0 to a1
}

/**
 * Computes hint bit indicating whether the low bits of the input element overflow into the high bits.
 *
 * [a0] - low bits of input element.
 * [a1] - high bits of input element.
 *
 * Returns true if overflow.
 */
internal fun makeHint(a0: Int, a1: Int, params: DilithiumParams): Boolean =
    a0 > params.GAMMA2 || a0 < -params.GAMMA2 || (a0 == -params.GAMMA2 && a1 != 0)

/**
 * Corrects high bits according to hint.
 *
 * Returns corrected high bits.
 */
internal fun useHint(a: Int, hint: Boolean, params: DilithiumParams): Int {
    val (a0, a1) = decompose(a, params)
    if (!hint)
        return a1

    return when (params.GAMMA2) {
        (DILITHIUM_Q - 1) / 32 -> if (a0 > 0) (a1 + 1) and 0xf
        else (a1 - 1) and 0xf
        (DILITHIUM_Q - 1) / 88 ->
            if (a0 > 0)
                if (a1 == 43) 0 else a1 + 1
            else
                if (a1 == 0) 43 else a1 - 1
        else -> error("unreachable code")
    }
}