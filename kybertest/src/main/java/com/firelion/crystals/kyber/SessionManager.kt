package com.firelion.crystals.kyber

import android.util.Log
import com.firelion.crystals.util.KyberParams.Companion.KYBER_SYMMETRIC_BYTES
import com.firelion.crystals.util.kexAkeInitA
import com.firelion.crystals.util.kexAkeSharedA
import com.firelion.crystals.util.kexAkeSharedB
import java.io.InputStream
import java.io.OutputStream
import java.security.spec.KeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlin.concurrent.thread


class SessionManager(
    private val kyberManager: KyberManager,
    private val inputStream: InputStream,
    private val outputStream: OutputStream,
    private val mainActivity: MainActivity
) {
    private lateinit var key: SecretKey
    private lateinit var cipher: Cipher

    private val otherPublicKey = ByteArray(kyberManager.params.KYBER_PUBLIC_KEY_BYTES)
    private val reader = thread(start = false) {
        try {
            val c = Cipher.getInstance("AES/CFB/PKCS5Padding")
                .apply { init(Cipher.DECRYPT_MODE, key) }

            val buf = ByteArray(4)

            while (inputStream.available() != -1) {
                inputStream.readToBuffer(buf)
                val len = buf.fold(0) { acc, i -> acc shl 8 or (i.toInt() and 0xff) }

                val buf1 = ByteArray(len)
                inputStream.readToBuffer(buf1)

                val l1 = c.doFinal(buf1, 0, len, buf1)
                mainActivity.appendHistoryLn(String(buf1, 0, l1))
            }
        } catch (e: InterruptedException) {
            Log.d("SessionManager", "interrupted", e)
        } catch (e: Exception) {
            e.printStackTrace()
            mainActivity.appendHistory(mainActivity.getString(R.string.error_closing_connection))
        }
    }

    fun startClient() {
        mainActivity.executor.execute {
            val buf = ByteArray(4)
            inputStream.readToBuffer(buf)
            if (String(buf) != "kbrt") {
                mainActivity.appendHistoryLn(mainActivity.getString(R.string.not_a_kyber_server))
                closeSession()
            }
            inputStream.readToBuffer(otherPublicKey)

            outputStream.write(kyberManager.publicKey)
            outputStream.flush()

            val ephemeralPrivateKey = ByteArray(kyberManager.params.KYBER_PRIVATE_KEY_BYTES)

            val sendA = ByteArray(kyberManager.params.KEX_AKE_SEND_A_BYTES)
            val sendB = ByteArray(kyberManager.params.KEX_AKE_SEND_B_BYTES)

            val tk = ByteArray(KYBER_SYMMETRIC_BYTES)
            val ka = ByteArray(KYBER_SYMMETRIC_BYTES)

            mainActivity.appendHistoryLn(mainActivity.getString(R.string.step1))
            kexAkeInitA(sendA, tk, ephemeralPrivateKey, otherPublicKey, kyberManager.params)

            outputStream.write(sendA)
            outputStream.flush()

            inputStream.readToBuffer(sendB)

            mainActivity.appendHistoryLn(mainActivity.getString(R.string.step3))
            kexAkeSharedA(ka, sendB, tk, ephemeralPrivateKey, kyberManager.privateKey, kyberManager.params)

            genAesKey(ka)
            reader.start()

            mainActivity.appendHistoryLn(
                String.format(
                    mainActivity.getString(R.string.connected_successfully),
                    ka.toHexString()
                )
            )
        }
    }

    fun startServer() {
        mainActivity.executor.execute {
            outputStream.write("kbrt".toByteArray())
            outputStream.write(kyberManager.publicKey)
            outputStream.flush()

            inputStream.readToBuffer(otherPublicKey)

            val sendA = ByteArray(kyberManager.params.KEX_AKE_SEND_A_BYTES)
            val sendB = ByteArray(kyberManager.params.KEX_AKE_SEND_B_BYTES)

            val kb = ByteArray(KYBER_SYMMETRIC_BYTES)

            inputStream.readToBuffer(sendA)

            mainActivity.appendHistoryLn(mainActivity.getString(R.string.step2))
            kexAkeSharedB(sendB, kb, sendA, kyberManager.privateKey, otherPublicKey, kyberManager.params)

            outputStream.write(sendB)
            outputStream.flush()

            genAesKey(kb)
            reader.start()

            mainActivity.appendHistoryLn(
                String.format(
                    mainActivity.getString(R.string.connected_successfully),
                    kb.toHexString()
                )
            )
        }
    }

    private fun genAesKey(key: ByteArray) {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec: KeySpec = PBEKeySpec(key.map { it.toChar() }.toCharArray(), ByteArray(8), 65536, 256)
        this.key = factory.generateSecret(spec)

        cipher = Cipher.getInstance("AES/CFB/PKCS5Padding")
            .apply { init(Cipher.ENCRYPT_MODE, this@SessionManager.key) }
    }

    fun send(mes: String) {
        mainActivity.executor.execute {
            synchronized(cipher) {
                val buf = cipher.doFinal(mes.toByteArray())
                outputStream.write(buf.size ushr 24)
                outputStream.write(buf.size ushr 16)
                outputStream.write(buf.size ushr 8)
                outputStream.write(buf.size ushr 0)
                outputStream.write(buf)
                outputStream.flush()
            }
        }
    }

    fun closeSession() {
        if (reader.isAlive) reader.interrupt()
        inputStream.close()
        outputStream.close()
        key.destroy()
    }
}