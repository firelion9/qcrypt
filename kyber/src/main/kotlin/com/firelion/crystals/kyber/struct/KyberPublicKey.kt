package com.firelion.crystals.kyber.struct

import com.firelion.crystals.kyber.util.KyberParams
import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_SYMMETRIC_BYTES

internal data class KyberPublicKey(
    val key: PolynomialVector,
    val seed: ByteArray,
    private val KYBER_POLYNOMIAL_VECTOR_BYTES: Int
) {
//    override fun getEncoded(): ByteArray = getEncoded(out = ByteArray(KYBER_POLYNOMIAL_VECTOR_BYTES + KYBER_SYMMETRIC_BYTES))

    constructor(params: KyberParams) : this(
        PolynomialVector(params),
        ByteArray(KYBER_SYMMETRIC_BYTES),
        params.KYBER_POLYNOMIAL_VECTOR_BYTES
    )

    fun getEncoded(out: ByteArray): ByteArray {
        key.toBytes(out)
        System.arraycopy(seed, 0, out, KYBER_POLYNOMIAL_VECTOR_BYTES, KYBER_SYMMETRIC_BYTES)
        return out
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as KyberPublicKey

        if (key != other.key) return false
        if (!seed.contentEquals(other.seed)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = key.hashCode()
        result = 31 * result + seed.contentHashCode()
        return result
    }
}