package com.firelion.crystals.struct

import com.firelion.crystals.util.KyberParams

internal data class CipherText(val b: PolynomialVector, val v: Polynomial) {
    constructor(params: KyberParams) : this(PolynomialVector(params), Polynomial())
}