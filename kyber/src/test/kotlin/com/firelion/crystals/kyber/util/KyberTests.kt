package com.firelion.crystals.kyber.util

import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_INDCPA_MESSAGE_BYTES
import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_SHARED_SECRET_BYTES
import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_SYMMETRIC_BYTES
import java.security.SecureRandom
import kotlin.random.Random
import kotlin.test.Test

internal class KyberTests {
    private val params = Kyber1024(SecureRandom.getInstanceStrong())

    @Test
    fun `assert kem decrypt inverses encrypt`() {
        val publicKey = ByteArray(params.KYBER_PUBLIC_KEY_BYTES)
        val privateKey = ByteArray(params.KYBER_PRIVATE_KEY_BYTES)

        val text = ByteArray(params.KYBER_CIPHER_TEXT_BYTES)
        val ss1 = ByteArray(KYBER_SHARED_SECRET_BYTES)
        val ss2 = ByteArray(KYBER_SHARED_SECRET_BYTES)

        cryptoKemKeyPair(publicKey, privateKey, params)

        cryptoKemEncrypt(publicKey, text, 0, ss1, 0, params)
        cryptoKemDecrypt(privateKey, ss2, 0, text, 0, params)

        assert(ss1.contentEquals(ss2))
    }

    @Test
    fun `assert indcpa decrypt(encrypt(x)) === x`() {
        val publicKey = ByteArray(params.KYBER_PUBLIC_KEY_BYTES)
        val privateKey = ByteArray(params.KYBER_PRIVATE_KEY_BYTES)

        val mes = ByteArray(KYBER_INDCPA_MESSAGE_BYTES).apply { Random.nextBytes(this) }
        val coins = ByteArray(KYBER_SYMMETRIC_BYTES)
        val cipherText = ByteArray(params.KYBER_INDCPA_BYTES)
        val mes2 = ByteArray(KYBER_SYMMETRIC_BYTES)

        indcpaKeyPair(publicKey, privateKey, params)

        indcpaEncrypt(mes, publicKey, 0, coins, 0, cipherText, 0, params)
        indcpaDecrypt(cipherText, 0, privateKey, mes2, 0, params)

        assert(mes.contentEquals(mes2))
    }

    @Test
    fun `test kex`() {
        val publicKeyA = ByteArray(params.KYBER_PUBLIC_KEY_BYTES)
        val publicKeyB = ByteArray(params.KYBER_PUBLIC_KEY_BYTES)

        val privateKeyA = ByteArray(params.KYBER_PRIVATE_KEY_BYTES)
        val privateKeyB = ByteArray(params.KYBER_PRIVATE_KEY_BYTES)

        val ephemeralPrivateKey = ByteArray(params.KYBER_PRIVATE_KEY_BYTES)

        val uakeSendA = ByteArray(params.KEX_UAKE_SEND_A_BYTES)
        val uakeSendB = ByteArray(params.KEX_UAKE_SEND_B_BYTES)
        val akeSendA = ByteArray(params.KEX_AKE_SEND_A_BYTES)
        val akeSendB = ByteArray(params.KEX_AKE_SEND_B_BYTES)

        val tk = ByteArray(KYBER_SYMMETRIC_BYTES)
        val ka = ByteArray(KYBER_SYMMETRIC_BYTES)
        val kb = ByteArray(KYBER_SYMMETRIC_BYTES)


        cryptoKemKeyPair(publicKeyA, privateKeyA, params) // Generate static key for Alice
        cryptoKemKeyPair(publicKeyB, privateKeyB, params) // Generate static key for Bob

        // Perform unilaterally authenticated key exchange
        kexUakeInitA(uakeSendA, tk, ephemeralPrivateKey, publicKeyB, params) // Run by Alice
        kexUakeSharedB(uakeSendB, kb, uakeSendA, privateKeyB, params) // Run by Bob
        kexUakeSharedA(ka, uakeSendB, tk, ephemeralPrivateKey, params) // Run by Alice

        assert(ka.contentEquals(kb))
        ka.fill(0)
        assert(!ka.contentEquals(kb))


        // Perform mutually authenticated key exchange
        kexAkeInitA(akeSendA, tk, ephemeralPrivateKey, publicKeyB, params) // Run by Alice
        kexAkeSharedB(akeSendB, kb, akeSendA, privateKeyB, publicKeyA, params) // Run by Bob
        kexAkeSharedA(ka, akeSendB, tk, ephemeralPrivateKey, privateKeyA, params) // Run by Alice

        assert(ka.contentEquals(kb))
        ka.fill(0)
        assert(!ka.contentEquals(kb))
    }
}