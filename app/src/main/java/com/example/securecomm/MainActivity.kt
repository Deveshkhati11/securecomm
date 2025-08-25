package com.example.securesomm

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Example usage
        val keyPair1 = CryptoUtils.generateKeyPair()
        val keyPair2 = CryptoUtils.generateKeyPair()

        val shared1 = CryptoUtils.generateSharedSecret(keyPair1.private, keyPair2.public)
        val shared2 = CryptoUtils.generateSharedSecret(keyPair2.private, keyPair1.public)

        println("Shared1: ${shared1.encoded.contentToString()}")
        println("Shared2: ${shared2.encoded.contentToString()}")
    }
}
