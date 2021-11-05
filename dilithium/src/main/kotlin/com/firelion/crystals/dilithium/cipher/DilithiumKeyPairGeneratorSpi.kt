package com.firelion.crystals.dilithium.cipher

import com.firelion.crystals.dilithium.util.*
import java.security.InvalidParameterException
import java.security.KeyPair
import java.security.KeyPairGeneratorSpi
import java.security.SecureRandom

class DilithiumKeyPairGeneratorSpi : KeyPairGeneratorSpi() {
    private lateinit var params: DilithiumParams

    override fun initialize(keysize: Int, random: SecureRandom) {
        params = when (keysize) {
            2 -> Dilithium2(false, random)
            3 -> Dilithium3(false, random)
            5 -> Dilithium5(false, random)
            else -> throw InvalidParameterException()
        }
    }

    override fun generateKeyPair(): KeyPair {
        val publicKey = ByteArray(params.CRYPTO_PUBLIC_KEY_BYTES)
        val privateKey = ByteArray(params.CRYPTO_PRIVATE_KEY_BYTES)

        dilithiumKeypair(publicKey, privateKey, params)

        return KeyPair(DilithiumPublicKey(publicKey, params), DilithiumPrivateKey(privateKey, params))
    }
}