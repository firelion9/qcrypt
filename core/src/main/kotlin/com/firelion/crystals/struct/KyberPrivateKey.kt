package com.firelion.crystals.struct

import com.firelion.crystals.util.KyberParams

internal data class KyberPrivateKey(val key: PolynomialVector) {
    //    override fun getEncoded(): ByteArray = getEncoded(out = ByteArray(KYBER_POLYNOMIAL_VECTOR_BYTES))

    constructor(params: KyberParams) : this(PolynomialVector(params))

    fun getEncoded(out: ByteArray): ByteArray {
        key.toBytes(out)
        return out
    }
}