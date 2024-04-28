package me.tatarka.webpush

import okio.Buffer
import okio.BufferedSource
import okio.ByteString
import okio.IOException
import okio.Source
import okio.Timeout
import okio.buffer
import okio.cipherSource
import java.security.Key
import java.security.interfaces.ECKey
import java.security.interfaces.ECPublicKey
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal fun <PK> aes128gcmEncrypt(
    authSecret: ByteString,
    publicKey: ECPublicKey,
    privateKey: PK,
    clientPublicKey: ByteString,
    body: BufferedSource,
    salt: ByteString,
    paddingStrategy: PaddingStrategy,
): WebPush where PK : Key, PK : ECKey {
    // later versions include it in encoded data instead
    val headers = listOf(
        WebPush.HeaderContentEncoding to WebPush.ContentEncoding.aes128gcm.toString()
    )

    val localPublicKeyBytes = pointEncode(publicKey.w)
    val remotePublicKeyBytes = clientPublicKey.toByteArray()

    val info = info(remotePublicKeyBytes, localPublicKeyBytes)
    val salt = salt.toByteArray()

    val (key, nonce) = calculateSecretKeyAndNonce(
        authSecret = authSecret,
        localPrivateKey = privateKey,
        remotePublicKey = remotePublicKeyBytes,
        salt = salt,
        info = info
    )

    val decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding")
    decryptionCipher.init(
        Cipher.ENCRYPT_MODE,
        SecretKeySpec(key, "AES"),
        GCMParameterSpec(16 * 8, nonce)
    )

    val paddedBody = when (paddingStrategy) {
        PaddingStrategy.Zero -> AppendZeroPadSource(body)
        PaddingStrategy.MultipleOf128 -> Append128PadSource(body)
    }
    val encryptedBody = paddedBody.cipherSource(decryptionCipher)
    val bodyWithHeader = ContentHeaderSource(salt, localPublicKeyBytes, encryptedBody)

    return WebPush(
        headers = headers,
        encryptedBody = bodyWithHeader
    )
}

internal fun <PK> aes128gcmDecrypt(
    authSecret: ByteString,
    publicKey: ECPublicKey,
    privateKey: PK,
    encryptedBody: Source,
): Source where PK : Key, PK : ECKey {
    val localPublicKeyBytes = pointEncode(publicKey.w)

    val source = encryptedBody.buffer()
    val salt = source.readByteArray(16)
    source.skip(4) // skip rs
    val idLen = source.readByte()
    val remotePublicKeyBytes = source.readByteArray(idLen.toLong())

    val info = info(localPublicKeyBytes, remotePublicKeyBytes)

    val (key, nonce) = calculateSecretKeyAndNonce(
        authSecret = authSecret,
        localPrivateKey = privateKey,
        remotePublicKey = remotePublicKeyBytes,
        salt = salt,
        info = info
    )

    val decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding")
    decryptionCipher.init(
        Cipher.DECRYPT_MODE,
        SecretKeySpec(key, "AES"),
        GCMParameterSpec(16 * 8, nonce)
    )

    return StripTrailingPaddingSource(source.cipherSource(decryptionCipher))
}

private fun info(
    clientKey: ByteArray,
    serverKey: ByteArray,
): ByteString {
    return Buffer()
        .writeUtf8("WebPush: info")
        .writeByte(0)
        .write(clientKey)
        .write(serverKey)
        .readByteString()
}

private fun <PK> calculateSecretKeyAndNonce(
    authSecret: ByteString,
    localPrivateKey: PK,
    remotePublicKey: ByteArray,
    salt: ByteArray,
    info: ByteString,
): Pair<ByteArray, ByteArray> where PK : Key, PK : ECKey {
    val sharedSecret = computeSharedSecret(
        localPrivateKey,
        pointDecode(remotePublicKey)
    )

    fun buildInfo(encoding: String): ByteArray {
        return Buffer()
            .writeUtf8("Content-Encoding: ")
            .writeUtf8(encoding)
            .writeByte(0)
            .readByteArray()
    }

    val combinedKey = computeHkdf(
        sharedSecret,
        authSecret.toByteArray(),
        info.toByteArray(),
        32
    )

    val key = computeHkdf(
        combinedKey,
        salt,
        buildInfo("aes128gcm"),
        16
    )

    val nonce = computeHkdf(
        combinedKey,
        salt,
        buildInfo("nonce"),
        12
    )

    return key to nonce
}

/**
 * Strips the padding from the end of the plaintext source. As we are only decoding one block so
 * this can be a separate step from decryption itself.
 */
private class StripTrailingPaddingSource(source: Source) : Source {

    private val source = SizeRestrictedSource(PAYLOAD_BOCK_SIZE, source).buffer()
    private var blockWithoutPadding: Buffer? = null

    override fun read(sink: Buffer, byteCount: Long): Long {
        val blockWithoutPadding = blockWithoutPadding ?: run {
            // Currently only supporting a single block so read to the end, then strip the padding
            // by looking for a 2 backwards from the padded zeros.
            val outBuffer = Buffer()
            source.request(PAYLOAD_BOCK_SIZE.toLong())
            //TODO: may be a faster way to search for this
            var paddingStart = -1L
            for (i in source.buffer.size - 1 downTo 0) {
                when (source.buffer[i]) {
                    2.toByte() -> {
                        paddingStart = i
                        break
                    }
                    0.toByte() -> {
                        // expected
                    }
                    else -> {
                        throw IOException("Invalid padding")
                    }
                }
            }
            if (paddingStart == -1L) {
                throw IOException("Missing padding")
            }
            outBuffer.write(source, paddingStart)
            outBuffer.also { blockWithoutPadding = it }
        }
        return blockWithoutPadding.read(sink, byteCount)
    }

    override fun close() {
        source.close()
    }

    override fun timeout(): Timeout {
        return source.timeout()
    }
}

/**
 * Prepends the source with the content header.
 */
private class ContentHeaderSource(
    salt: ByteArray,
    publicKey: ByteArray,
    private val source: Source
) : Source {

    private val header = Buffer()
        .write(salt) // salt
        .writeInt(PAYLOAD_BOCK_SIZE) // rs
        .writeByte(publicKey.size) // idlen
        .write(publicKey) // keyid

    override fun read(sink: Buffer, byteCount: Long): Long {
        return if (header.exhausted()) {
            source.read(sink, byteCount)
        } else {
            header.read(sink, byteCount)
        }
    }

    override fun close() {
        source.close()
    }

    override fun timeout(): Timeout {
        return source.timeout()
    }
}

private class AppendZeroPadSource(source: Source) : Source {
    private val source = SizeRestrictedSource(3993, source)
    private var paddingWritten = false

    override fun read(sink: Buffer, byteCount: Long): Long {
        val bytesRead = source.read(sink, byteCount)
        if (bytesRead == -1L && !paddingWritten) {
            sink.writeByte(2) // last record padding delimiter
            paddingWritten = true
            return 1
        }
        return bytesRead
    }

    override fun close() {
        source.close()
    }

    override fun timeout(): Timeout {
        return source.timeout()
    }

}

private class Append128PadSource(source: Source) : Source {
    private val source = SizeRestrictedSource(3993, source)
    private var totalByteCount = 0L
    private var paddingBytes: Buffer? = null

    override fun read(sink: Buffer, byteCount: Long): Long {
        val readBytes = source.read(sink, byteCount)
        if (readBytes == -1L) {
            val paddingBytes = paddingBytes ?: run {
                val padding = 128 - (totalByteCount % 128)
                Buffer()
                    .writeByte(2)
                    .apply {
                        for (i in 0 until padding) {
                            writeByte(0)
                        }
                    }.also { paddingBytes = it }
            }
            return paddingBytes.read(sink, byteCount)
        }
        totalByteCount += readBytes
        return readBytes
    }

    override fun close() {
        source.close()
    }

    override fun timeout(): Timeout {
        return source.timeout()
    }
}