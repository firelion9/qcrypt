package com.firelion.crystals.kyber.util

import com.firelion.crystals.kyber.struct.Polynomial
import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_ETA2
import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_N

/**
 * load 4 bytes into a 32-bit integer in little-endian order
 */
private fun load32LittleEndian(x: ByteArray, offset: Int) =
    x[offset].toIntUnsigned() or
            (x[offset + 1].toIntUnsigned() shl 8) or
            (x[offset + 2].toIntUnsigned() shl 16) or
            (x[offset + 3].toIntUnsigned() shl 24)

/**
 * load 3 bytes into a 32-bit integer in little-endian order.
 * This function is only needed for Kyber-512
 */
private fun load24LittleEndian(x: ByteArray, offset: Int) =
    x[offset].toIntUnsigned() or
            (x[offset + 1].toIntUnsigned() shl 8) or
            (x[offset + 2].toIntUnsigned() shl 16)

/**
 * Given an array of uniformly random bytes, compute polynomial with coefficients
 * distributed according to a centered binomial distribution
 * with parameter eta=2
 */
internal fun cbd2(bytes: ByteArray, out: Polynomial) {
    (0 until KYBER_N / 8).forEach { i ->
        val t = load32LittleEndian(bytes, 4 * i)
        var d = t and 0x55555555
        d += (t shr 1) and 0x55555555

        (0 until 8).forEach { j ->
            val a = (d ushr (4 * j + 0)) and 0x3
            val b = (d ushr (4 * j + 2)) and 0x3
            out.coefficients[8 * i + j] = a - b
        }
    }
}

/**
 * Given an array of uniformly random bytes, compute polynomial with coefficients
 * distributed according to a centered binomial distribution with parameter eta=3.
 * This function is only needed for Kyber-512
 */
internal fun cbd3(bytes: ByteArray, out: Polynomial) {
    (0 until KYBER_N / 4).forEach { i ->
        val t = load24LittleEndian(bytes, 3 * i)
        var d = t and 0x00249249
        d += (t ushr 1) and 0x00249249
        d += (t ushr 2) and 0x00249249

        (0 until 4).forEach { j ->
            val a = (d ushr (6 * j + 0)) and 0x7
            val b = (d ushr (6 * j + 3)) and 0x7
            out.coefficients[4 * i + j] = a - b
        }
    }
}

internal fun cbdEta1(bytes: ByteArray, out: Polynomial, params: KyberParams) {
    when (params.KYBER_ETA1) {
        2 -> cbd2(bytes, out)
        3 -> cbd3(bytes, out)
        else -> throw AssertionError("illegal KYBER_ETA1 value ${params.KYBER_ETA1}")
    }
}

internal fun cbdEta2(bytes: ByteArray, out: Polynomial) {
    when (KYBER_ETA2) {
        2 -> cbd2(bytes, out)
        else -> throw AssertionError("illegal KYBER_ETA2 value $KYBER_ETA2")
    }
}
