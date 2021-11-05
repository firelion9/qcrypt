package com.firelion.crystals.dilithium.cipher

import com.firelion.crystals.dilithium.struct.ByteArrayView
import com.firelion.crystals.dilithium.util.signature
import com.firelion.crystals.dilithium.util.verifySignature
import java.security.InvalidKeyException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SignatureSpi
import kotlin.math.min

class DilithiumSignatureSpi : SignatureSpi() {
    private var privateKey: DilithiumPrivateKey? = null
    private var publicKey: DilithiumPublicKey? = null

    private var message: ByteArray = ByteArray(64)
    private var messageLen = 0

    private fun reallocateMessage(minExtraSize: Int) {
        val newSize = min(message.size * 2, message.size + minExtraSize)

        val newMessage = ByteArray(newSize)
        System.arraycopy(message, 0, newMessage, 0, messageLen)
        message = newMessage
    }

    private fun ensureExtraSize(extraSize: Int) {
        if (message.size - messageLen < extraSize)
            reallocateMessage(extraSize + messageLen - message.size)
    }

    private fun pushMessage(byte: Byte) {
        ensureExtraSize(1)
        message[messageLen++] = byte
    }

    private fun pushMessage(bytes: ByteArray, offset: Int = 0, size: Int = bytes.size - offset) {
        require(offset > 0 && offset + size < bytes.size) {
            "out of bounds: offset=$offset, size=$size, array size=${bytes.size}"
        }
        ensureExtraSize(size)

        System.arraycopy(bytes, offset, message, messageLen, size)
        messageLen += size
    }

    private fun ensureInit() {
        if (publicKey == null && privateKey == null) error("not initialized")
    }

    override fun engineInitVerify(publicKey: PublicKey) {
        this.publicKey = (publicKey as? DilithiumPublicKey) ?: throw InvalidKeyException()
        this.privateKey = null
        message = ByteArray(64)
        messageLen = 0
    }

    override fun engineInitSign(privateKey: PrivateKey?) {
        this.privateKey = (privateKey as? DilithiumPrivateKey) ?: throw InvalidKeyException()
        this.publicKey = null
        message = ByteArray(64)
        messageLen = 0
    }

    override fun engineUpdate(b: Byte) {
        ensureInit()
        pushMessage(b)
    }

    override fun engineUpdate(b: ByteArray, off: Int, len: Int) {
        ensureInit()
        pushMessage(b, off, len)
    }

    override fun engineSign(): ByteArray {
        val privateKey = privateKey ?: error("engine should be initialized for signing")

        val sign = ByteArray(privateKey.params.SIGNATURE_BYTES)

        signature(ByteArrayView(sign), ByteArrayView(message), messageLen, privateKey.encoded, privateKey.params)

        return sign
    }

    override fun engineVerify(sigBytes: ByteArray): Boolean {
        val publicKey = publicKey ?: error("engine should be initialized for verifying")

        return verifySignature(
            ByteArrayView(sigBytes),
            sigBytes.size,
            ByteArrayView(message),
            messageLen,
            publicKey.encoded,
            publicKey.params
        )
    }

    override fun engineSetParameter(param: String?, value: Any?) {
        throw UnsupportedOperationException()
    }

    override fun engineGetParameter(param: String?): Any {
        throw UnsupportedOperationException()
    }
}