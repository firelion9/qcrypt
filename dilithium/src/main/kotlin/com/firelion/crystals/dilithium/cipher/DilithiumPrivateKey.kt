package com.firelion.crystals.dilithium.cipher

import com.firelion.crystals.dilithium.util.DilithiumParams
import java.security.PrivateKey

class DilithiumPrivateKey(private val privateKey: ByteArray, val params: DilithiumParams) : PrivateKey {
    override fun getAlgorithm(): String = "CRYSTALS-Dilithium"

    override fun getFormat(): String = "RAW"

    override fun getEncoded(): ByteArray = privateKey
}