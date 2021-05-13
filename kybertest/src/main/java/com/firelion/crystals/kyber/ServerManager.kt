package com.firelion.crystals.kyber

import android.util.Log
import java.net.NetworkInterface
import java.net.ServerSocket
import kotlin.concurrent.thread

class ServerManager(private val server: ServerSocket, private val mainActivity: MainActivity) {
    private val thread = thread(start = false) {
        try {
            val soc = server.accept()
            mainActivity.openSession(soc.getInputStream(), soc.getOutputStream(), true)
        } catch (e: Exception) {
            Log.w("ServerManager", "server interrupted with exception", e)
        } finally {
            if (!server.isClosed) server.close()
        }
    }

    fun start() {
        mainActivity.appendHistoryLn(mainActivity.getString(R.string.starting_server))
        thread.start()
        mainActivity.executor.execute {
            val myIp = NetworkInterface.getNetworkInterfaces()
                .asSequence()
                .flatMap { it.inetAddresses.asSequence() }
                .map { it.hostAddress }
                .filter { it.matches("\\d*\\.\\d*\\.\\d*\\.\\d*".toRegex()) }
                .filterNot { it == "127.0.0.1" }
                .joinToString()

            mainActivity.appendHistoryLn(String.format(mainActivity.getString(R.string.started_successfully), myIp))
        }
    }

    fun stop() {
        if (thread.isAlive) {
            mainActivity.appendHistoryLn(mainActivity.getString(R.string.interrupting_server))
            server.close()
            mainActivity.appendHistoryLn(mainActivity.getString(R.string.interrupted_successfully))
        }
    }
}