package com.firelion.crystals.dilithium.util

import com.firelion.crystals.dilithium.struct.ByteArrayView
import org.junit.Test
import java.security.SecureRandom
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.test.fail

private const val MESSAGE_SIZE = 64

class DilithiumTests {
    private fun assertByteArrayEquals(expected: ByteArray, actual: ByteArray, message: String = "assertion failed") {
        assertTrue(expected.contentEquals(actual), message)
    }

    @Test
    fun `test signing and verifying`() {
        val random = SecureRandom.getInstanceStrong()
        listOf(false, true).forEach { randomized ->
            listOf(
                Dilithium2(randomized, random),
                Dilithium3(randomized, random),
                Dilithium5(randomized, random)
            ).forEach { params ->
                try {
                    doTestsFor(params)
                } catch (e: Throwable) {
                    fail("test failed for parameter set $params (randomized = $randomized)", e)
                }
            }
        }
    }

    private fun doTestsFor(params: DilithiumParams) {
        val message = ByteArray(MESSAGE_SIZE + params.SIGNATURE_BYTES)
        val message2 = ByteArray(MESSAGE_SIZE + params.SIGNATURE_BYTES)
        val signedMessage = ByteArray(MESSAGE_SIZE + params.SIGNATURE_BYTES)
        val publicKey = ByteArray(params.CRYPTO_PUBLIC_KEY_BYTES)
        val privateKey = ByteArray(params.CRYPTO_PRIVATE_KEY_BYTES)

        randomBytes(ByteArrayView(message), MESSAGE_SIZE, params)

        dilithiumKeypair(publicKey, privateKey, params)
        val signedMessageLength = dilithiumSign(signedMessage, message, MESSAGE_SIZE, privateKey, params)
        var messageLength = dilithiumOpenSignature(message2, signedMessage, signedMessageLength, publicKey, params)

        assertNotEquals(-1, messageLength, "Verification failed")

        assertEquals(MESSAGE_SIZE + params.SIGNATURE_BYTES, signedMessageLength, "Signed message lengths wrong")

        assertEquals(MESSAGE_SIZE, messageLength, "Message lengths wrong")

        assertByteArrayEquals(message, message2, "Messages don't match")

        signedMessage.indices.random().let {
            signedMessage[it] = Random.nextBits(8).toByte()
        }

        messageLength = dilithiumOpenSignature(message2, signedMessage, signedMessageLength, publicKey, params)
        assertEquals(-1, messageLength, "Trivial forgeries possible")
    }
}