package com.firelion.crystals.kyber

import android.content.Context
import com.firelion.crystals.util.Kyber1024
import com.firelion.crystals.util.kexKeyPair
import org.bouncycastle.util.Fingerprint
import java.io.File
import java.security.SecureRandom

class KyberManager(private val context: Context) {
    val params = Kyber1024(SecureRandom.getInstance("SHA1PRNG"))
    val publicKey: ByteArray = ByteArray(params.KYBER_PUBLIC_KEY_BYTES)
    val privateKey: ByteArray = ByteArray(params.KYBER_PRIVATE_KEY_BYTES)

    init {
        val dir = context.filesDir
        val pk = File(dir, "pk")
        val sk = File(dir, "sk")

        if (!pk.exists() || !sk.exists()) regenerateKeys()
        else {
            pk.inputStream().use { it.read(publicKey) }
            sk.inputStream().use { it.read(privateKey) }
        }
    }

    fun regenerateKeys() {
        val dir = context.filesDir
        val pk = File(dir, "pk")
        val sk = File(dir, "sk")

        kexKeyPair(publicKey, privateKey, params)
        pk.writeBytes(publicKey)
        sk.writeBytes(privateKey)
    }

    fun fingerprint(): String =
        Fingerprint.calculateFingerprint(publicKey)
            .toHexString()

    fun dispose() {
        privateKey.fill(0)
        publicKey.fill(0)
    }
}