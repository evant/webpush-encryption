package me.tatarka.webpush

import okio.ByteString
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec

fun keyPair(publicKey: String, privateKey: String): KeyPair {
    return KeyPair(
        getEcPublicKey(publicKey.decodeBase64()!!.toByteArray()),
        getEcPrivateKey(privateKey.decodeBase64()!!.toByteArray())
    )
}

fun generateAuthSecret(): ByteString {
    return ByteArray(16).apply {
        SecureRandom().nextBytes(this)
    }.toByteString()
}

fun generateKeyPair(): KeyPair {
    return KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
}

fun generateKeyPairWithWrongAlgorithm(): KeyPair {
    return KeyPairGenerator.getInstance("RSA").apply {
        initialize(1024)
    }.generateKeyPair()
}

fun generateKeyPairWithWrongCurve(): KeyPair {
    return KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp128r1"))
    }.generateKeyPair()
}
