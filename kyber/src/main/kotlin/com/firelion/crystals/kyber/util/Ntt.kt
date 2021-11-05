package com.firelion.crystals.kyber.util

import com.firelion.crystals.kyber.struct.Polynomial
import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_N
import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_Q
import com.firelion.crystals.kyber.util.KyberParams.Companion.Q_INV

/**
 * Roots of unity modulo [KYBER_Q], used in NTT.
 */
private val zetas = intArrayOf(
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628
)

/**
 * Montgomery reduction; given a 32-bit integer, computes
 * 16-bit integer congruent to a * R^-1 mod q, where R=2^16.
 */
internal fun Int.montgomeryReduce(): Int {
    var t = (this * Q_INV).toShort().toInt()
    t = (this - t * KYBER_Q) shr 16
    return t
}

/**
 * Barrett reduction; given a 16-bit integer a, computes
 * centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}.
 */
internal fun Int.barrettReduce(): Int {
    var t: Int
    val v = ((1 shl 26) + KYBER_Q / 2) / KYBER_Q

    t = (v * this + (1 shl 25)) shr 26
    t *= KYBER_Q
    return this - t
}


infix fun Int.fqMul(other: Int): Int {
    return (this * other).montgomeryReduce()
}

internal fun IntArray.ntt() {
    val res = this
    var k = 1

    (7 downTo 1).forEach { pow ->
        val len = 1 shl pow

        (0 until 256 step 2 * len).forEach { start ->
            val zeta = zetas[k++]

            (start until start + len).forEach { j ->
                val t = zeta fqMul res[j + len]
                res[j + len] = res[j] - t
                res[j] = res[j] + t
            }
        }
    }
}

internal fun IntArray.inverseNtt() {
    val res = this

    val f = 1441 // mont^2/128

    var k = 127

    (1..7).forEach { pow ->
        val len = 1 shl pow

        (0 until 256 step 2 * len).forEach { start ->
            val zeta = zetas[k--]

            (start until start + len).forEach { j ->
                val t = res[j]
                res[j] = (t + res[j + len]).barrettReduce()
                res[j + len] = res[j + len] - t
                res[j + len] = zeta fqMul res[j + len]
            }
        }
    }

    res.mapInPlace { it fqMul f }
}

/**
 * Multiplication of polynomials in Zq[X]/(X^2-zeta).
 * Used for multiplication of elements in Rq in NTT domain.
 */
internal fun baseMul(
    left: Polynomial,
    leftOffset: Int,
    right: Polynomial,
    rightOffset: Int,
    zeta: Int,
    output: Polynomial,
    outputOffset: Int
) {
    output.coefficients[outputOffset] = left.coefficients[leftOffset + 1] fqMul right.coefficients[rightOffset + 1]
    output.coefficients[outputOffset] = output.coefficients[leftOffset] fqMul zeta
    output.coefficients[outputOffset] += left.coefficients[leftOffset] fqMul right.coefficients[rightOffset]
    output.coefficients[outputOffset + 1] = left.coefficients[leftOffset] fqMul right.coefficients[rightOffset + 1]
    output.coefficients[outputOffset + 1] += left.coefficients[leftOffset + 1] fqMul right.coefficients[rightOffset]
}

/**
 * Multiplication of two polynomials in NTT domain.
 */
internal fun baseMulMontgomery(left: Polynomial, right: Polynomial, output: Polynomial) {
    (0 until KYBER_N step 4).forEach { pos ->
        baseMul(left, pos, right, pos, zetas[64 + pos / 4], output, pos)
        baseMul(left, pos + 2, right, pos + 2, -zetas[64 + pos / 4], output, pos + 2)
    }
}