package com.firelion.crystals.dilithium.cipher

import com.firelion.crystals.dilithium.util.DilithiumParams
import java.security.PublicKey

class DilithiumPublicKey(private val publicKey: ByteArray, val params: DilithiumParams) : PublicKey {
    override fun getAlgorithm(): String = "CRYStALS-Dilithium"

    override fun getFormat(): String = "RAW"

    override fun getEncoded(): ByteArray = publicKey
}