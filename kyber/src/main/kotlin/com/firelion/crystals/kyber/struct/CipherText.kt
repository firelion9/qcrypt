package com.firelion.crystals.kyber.struct

import com.firelion.crystals.kyber.util.KyberParams

internal data class CipherText(val b: PolynomialVector, val v: Polynomial) {
    constructor(params: KyberParams) : this(PolynomialVector(params), Polynomial())
}