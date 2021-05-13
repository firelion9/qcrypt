package com.firelion.crystals.kyber

import android.annotation.SuppressLint
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors

private const val THE_PORT = 3329

class MainActivity : AppCompatActivity() {
    private lateinit var kyberManager: KyberManager
    private var sessionManager: SessionManager? = null
    private var serverManager: ServerManager? = null

    private lateinit var keysInfo: TextView
    private lateinit var history: TextView

    val executor = Executors.newFixedThreadPool(1)!!

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        kyberManager = KyberManager(this)

        history = findViewById(R.id.history)

        keysInfo = findViewById(R.id.currentStaticKeyInfo)
        updateStaticKeyInfo()

        with(findViewById<Button>(R.id.regenerateStaticKey)) {
            setOnClickListener {
                kyberManager.regenerateKeys()
                Toast.makeText(
                    this@MainActivity,
                    getString(R.string.keys_regenerated),
                    Toast.LENGTH_SHORT
                ).show()
                updateStaticKeyInfo()
            }
        }

        with(findViewById<Button>(R.id.startServer)) {
            setOnClickListener {
                serverManager?.stop()

                val serverManager = ServerManager(ServerSocket(THE_PORT), this@MainActivity)
                serverManager.start()
                this@MainActivity.serverManager = serverManager
                Toast.makeText(this@MainActivity, getString(R.string.server_started), Toast.LENGTH_SHORT).show()
            }
        }

        with(findViewById<Button>(R.id.connect)) {
            setOnClickListener {
                AlertDialog.Builder(this@MainActivity)
                    .setTitle(getString(R.string.connect_to))
                    .setView(
                        LayoutInflater.from(this@MainActivity)
                            .inflate(R.layout.edit_text_ip, parent as ViewGroup, false)
                    )
                    .setCancelable(true)
                    .setNegativeButton(getString(android.R.string.cancel)) { _, _ -> }
                    .setPositiveButton(getString(R.string.connect)) { dialog, _ ->
                        val text =
                            (dialog as AlertDialog).findViewById<EditText>(R.id.ip)!!.text.toString()

                        executor.execute {
                            try {
                                val soc = Socket(text, THE_PORT)
                                openSession(soc.getInputStream(), soc.getOutputStream(), false)
                            } catch (e: Exception) {
                                Log.w("openSession", "error", e)
                                appendHistoryLn(getString(R.string.cant_open_session))
                            }
                        }
                    }
                    .show()
            }
        }

        findViewById<EditText>(R.id.messageEditText).setOnEditorActionListener { v, _, _ ->
            val mes = v.text.toString()
            appendHistoryLn(mes)
            sessionManager?.send(mes)
            v.text = ""
            true
        }
    }

    private fun updateStaticKeyInfo() {
        keysInfo.text =
            String.format(getString(R.string.static_key_info_template), kyberManager.fingerprint())
    }

    override fun onDestroy() {
        super.onDestroy()
        kyberManager.dispose()
        sessionManager?.closeSession()
        serverManager?.stop()
    }

    fun openSession(inputStream: InputStream, outputStream: OutputStream, server: Boolean) {
        appendHistoryLn(getString(R.string.opening_session))
        sessionManager?.let {
            it.closeSession()
            appendHistoryLn(getString(R.string.previous_session_closed))
        }
        sessionManager = SessionManager(kyberManager, inputStream, outputStream, this)

        if (server) sessionManager?.startServer()
        else sessionManager?.startClient()
    }

    private val handler = Handler(Looper.getMainLooper())

    @SuppressLint("SetTextI18n")
    fun appendHistoryLn(mes: String) {
        handler.post {
            synchronized(history) {
                history.text = "${history.text}\n$mes"
            }
        }
    }

    @SuppressLint("SetTextI18n")
    fun appendHistory(mes: String) {
        handler.post {
            synchronized(history) {
                history.text = "${history.text}$mes"
            }
        }
    }
}