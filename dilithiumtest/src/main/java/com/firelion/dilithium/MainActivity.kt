package com.firelion.dilithium

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import com.firelion.crystals.dilithium.util.Dilithium3
import com.firelion.crystals.dilithium.util.DilithiumParams
import com.firelion.crystals.dilithium.util.dilithiumOpenSignature
import java.security.SecureRandom

private const val OPEN_SIGNED_FILE = 10
private const val OPEN_SIGNATURE = 11

class MainActivity : AppCompatActivity() {
    private val params: DilithiumParams = Dilithium3(false, SecureRandom())
    private lateinit var viewModel: MainViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        viewModel = ViewModelProvider(this, ViewModelProvider.AndroidViewModelFactory(application))
            .get(MainViewModel::class.java)

        val labelSignedFile: TextView = findViewById(R.id.label_file)
        val labelSignature: TextView = findViewById(R.id.label_sig)
        val labelValid: TextView = findViewById(R.id.label_valid)

        findViewById<Button>(R.id.btn_choose_file).setOnClickListener {
            openFile(OPEN_SIGNED_FILE)
        }
        findViewById<Button>(R.id.btn_choose_sig).setOnClickListener {
            openFile(OPEN_SIGNATURE)
        }

        viewModel.signedFile.observe(this) {
            labelSignedFile.text = it.toString()
            labelValid.text = ""
        }
        viewModel.signatureFile.observe(this) {
            labelSignature.text = it.toString()
            labelValid.text = ""
        }

        findViewById<Button>(R.id.btn_check).setOnClickListener {
            kotlin.runCatching {
                if (viewModel.signedFile.value == null || viewModel.signatureFile.value == null) {
                    Toast.makeText(this, getString(R.string.choose_files_first), Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }

                val message = contentResolver.openInputStream(viewModel.signedFile.value!!)!!.use { it.readBytes() }
                val sigPk = contentResolver.openInputStream(viewModel.signatureFile.value!!)!!.use { it.readBytes() }

                val publicKey = sigPk.asList().subList(0, params.CRYPTO_PUBLIC_KEY_BYTES).toByteArray()
                val sigMessage =
                    sigPk.asList().subList(params.CRYPTO_PUBLIC_KEY_BYTES, sigPk.size).toByteArray() + message

                if (dilithiumOpenSignature(message, sigMessage, sigMessage.size, publicKey, params) == -1) {
                    labelValid.text = getString(R.string.signature_invalid)
                    labelValid.setTextColor(Color.RED)
                } else {
                    labelValid.text = getString(R.string.signature_valid)
                    labelValid.setTextColor(Color.GREEN)
                }
            }.exceptionOrNull()?.let {
                labelValid.text = getString(R.string.signature_invalid)
                labelValid.setTextColor(Color.RED)
                it.printStackTrace()
            }
        }
    }

    private fun openFile(requestCode: Int) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }

        startActivityForResult(intent, requestCode)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (resultCode == RESULT_OK)
            when (requestCode) {
                OPEN_SIGNED_FILE -> {
                    viewModel.signedFile.value = data!!.data!!
                }
                OPEN_SIGNATURE -> {
                    viewModel.signatureFile.value = data!!.data!!
                }
            }
    }
}