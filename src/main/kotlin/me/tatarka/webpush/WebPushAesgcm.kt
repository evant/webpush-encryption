package me.tatarka.webpush

import okio.Buffer
import okio.BufferedSource
import okio.ByteString
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import okio.IOException
import okio.Source
import okio.Timeout
import okio.blackholeSink
import okio.buffer
import okio.cipherSource
import java.security.Key
import java.security.interfaces.ECKey
import java.security.interfaces.ECPublicKey
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal fun <PK> aesgcmEncrypt(
    authSecret: ByteString,
    publicKey: ECPublicKey,
    privateKey: PK,
    clientPublicKey: ByteString,
    body: BufferedSource,
    salt: ByteString,
    paddingStrategy: PaddingStrategy,
): WebPush where PK : Key, PK : ECKey {
    // draft version included key params in headers
    val headers = AesgcmEncoding(
        dh = pointEncode(publicKey.w).toByteString(),
        salt = salt,
    ).toHeaders()

    val localPublicKeyBytes = pointEncode(publicKey.w)
    val remotePublicKeyBytes = clientPublicKey.toByteArray()

    val context = context(remotePublicKeyBytes, localPublicKeyBytes)

    val (key, nonce) = calculateSecretKeyAndNonce(
        authSecret = authSecret,
        localPrivateKey = privateKey,
        remotePublicKey = clientPublicKey.toByteArray(),
        salt = salt.toByteArray(),
        context = context,
    )

    val decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding")
    decryptionCipher.init(
        Cipher.ENCRYPT_MODE,
        SecretKeySpec(key, "AES"),
        GCMParameterSpec(16 * 8, nonce)
    )

    val paddedBody = when (paddingStrategy) {
        PaddingStrategy.Zero -> PrependZeroPadSource(body)
        PaddingStrategy.MultipleOf128 -> PadTo128BytesSource(body)
    }

    val encryptedBody = paddedBody.cipherSource(decryptionCipher)

    return WebPush(
        headers = headers,
        encryptedBody = encryptedBody,
    )
}

internal fun <PK> aesgcmDecrypt(
    authSecret: ByteString,
    publicKey: ECPublicKey,
    privateKey: PK,
    headers: Headers,
    encryptedBody: Source,
): Source where PK : Key, PK : ECKey {
    val headerData = AesgcmEncoding.extract(headers)

    val localPublicKeyBytes = pointEncode(publicKey.w)
    val remotePublicKeyBytes = headerData.dh.toByteArray()

    val context = context(localPublicKeyBytes, remotePublicKeyBytes)

    val (key, nonce) = calculateSecretKeyAndNonce(
        authSecret = authSecret,
        localPrivateKey = privateKey,
        remotePublicKey = remotePublicKeyBytes,
        salt = headerData.salt.toByteArray(),
        context = context,
    )
    val decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding")
    decryptionCipher.init(
        Cipher.DECRYPT_MODE,
        SecretKeySpec(key, "AES"),
        GCMParameterSpec(16 * 8, nonce)
    )
    return StripLeadingPaddingSource(encryptedBody.cipherSource(decryptionCipher))
}

private fun context(
    clientKey: ByteArray,
    serverKey: ByteArray,
): ByteString {
    return Buffer()
        .writeUtf8("P-256")
        .writeByte(0)
        .writeByte(0)
        .writeByte(0x41)
        .write(clientKey)
        .writeByte(0)
        .writeByte(0x41)
        .write(serverKey)
        .readByteString()
}

private fun <PK> calculateSecretKeyAndNonce(
    authSecret: ByteString,
    localPrivateKey: PK,
    remotePublicKey: ByteArray,
    salt: ByteArray,
    context: ByteString,
): Pair<ByteArray, ByteArray> where PK : Key, PK : ECKey {

    val sharedSecret = computeSharedSecret(
        localPrivateKey,
        pointDecode(remotePublicKey)
    )

    fun buildInfo(encoding: String, context: ByteString? = null): ByteArray {
        return Buffer()
            .writeUtf8("Content-Encoding: ")
            .writeUtf8(encoding)
            .writeByte(0)
            .apply {
                if (context != null) {
                    write(context)
                }
            }
            .readByteArray()
    }

    val combinedKey = computeHkdf(
        sharedSecret,
        authSecret.toByteArray(),
        buildInfo("auth"),
        32
    )


    val key = computeHkdf(
        combinedKey,
        salt,
        buildInfo("aesgcm", context),
        16
    )

    val nonce = computeHkdf(
        combinedKey,
        salt,
        buildInfo("nonce", context),
        12
    )

    return key to nonce
}


private class AesgcmEncoding(
    val dh: ByteString,
    val salt: ByteString,
) {
    val encoding = WebPush.ContentEncoding.aesgcm

    fun toHeaders(): Headers {
        return listOf(
            "Content-Encoding" to encoding.toString(),
            "Crypto-Key" to "dh=${dh.base64Url().replace("=", "")}",
            "Encryption" to "salt=${salt.base64Url().replace("=", "")}",
        )
    }

    companion object {
        fun extract(headers: Headers): AesgcmEncoding {
            var dh: ByteString? = null
            var salt: ByteString? = null

            fun expect(name: String, value: String, offset: Int, expected: String): Int {
                if (offset > value.length || offset + expected.length > value.length) {
                    throw WebPushFormatException("$name parse error at: $offset")
                }
                if (value.substring(offset, offset + expected.length) != expected) {
                    throw WebPushFormatException("$name parse error at: $offset")
                }
                return offset + expected.length
            }

            for ((name, value) in headers) {
                when (name) {
                    "Crypto-Key" -> {
                        var offset = 0
                        offset = expect(name, value, offset, "dh=")
                        var endIndex = value.indexOf(';', startIndex = offset)
                        if (endIndex == -1) {
                            endIndex = value.length
                        }
                        dh = value.substring(offset, endIndex).decodeBase64()
                        if (dh == null) {
                            throw WebPushFormatException("Crypto-Key parse error at: $offset")
                        }
                    }

                    "Encryption" -> {
                        var offset = 0
                        offset = expect(name, value, offset, "salt=")
                        var endIndex = value.indexOf(';', startIndex = offset)
                        if (endIndex == -1) {
                            endIndex = value.length
                        }
                        salt = value.substring(offset, endIndex).decodeBase64()
                    }
                }
            }

            if (dh == null) {
                throw WebPushFormatException("Missing 'Crypto-Key' header")
            }
            if (salt == null) {
                throw WebPushFormatException("Missing 'Encryption' header")
            }

            return AesgcmEncoding(
                dh = dh,
                salt = salt
            )
        }
    }
}

/**
 * Strips the padding from the given plaintext source. As we are only decoding one block this can be
 * a separate step from decryption itself.
 */
private class StripLeadingPaddingSource(source: Source) : Source {

    private val source = SizeRestrictedSource(PAYLOAD_BOCK_SIZE, source)
    private var paddingRead = false

    override fun read(sink: Buffer, byteCount: Long): Long {
        if (!paddingRead) {
            val out = Buffer()
            if (source.read(out, 2) != 2L) {
                throw IOException("Incorrect padding")
            }
            val padding = out.readShort()
            if (padding > PAYLOAD_BOCK_SIZE) {
                throw IOException("Padding too large")
            }
            var bytesRead = 0L
            while (bytesRead < padding) {
                val newBytesRead = source.read(out, padding - bytesRead)
                if (newBytesRead == -1L) {
                    throw IOException("Incorrect padding")
                }
                //TODO: may be able to check 0 padding in larger chunks.
                while (!out.exhausted()) {
                    if (out.readByte() != 0.toByte()) {
                        throw IOException("Incorrect padding")
                    }
                }
                bytesRead += newBytesRead
            }
            paddingRead = true
        }
        return source.read(sink, byteCount)
    }

    override fun close() {
        source.close()
    }

    override fun timeout(): Timeout {
        return source.timeout()
    }
}

private class PrependZeroPadSource(source: Source): Source {

    private val source = SizeRestrictedSource(4077, source)
    private val paddingBytes = Buffer().writeShort(0)

    override fun read(sink: Buffer, byteCount: Long): Long {
        return if (paddingBytes.exhausted()) {
            source.read(sink, byteCount)
        } else {
            paddingBytes.read(sink, byteCount)
        }
    }

    override fun close() {
        source.close()
    }

    override fun timeout(): Timeout {
        return source.timeout()
    }
}

/*
 * Pads the source to a multiple of 128 bytes.
 */
private class PadTo128BytesSource(source: Source) : Source {

    private val source = SizeRestrictedSource(4077, source).buffer()
    private var paddingBytes: Buffer? = null

    override fun read(sink: Buffer, byteCount: Long): Long {
        val paddingBytes = paddingBytes ?: run {
            // Currently only supporting a single block, so we can read the entire thing to compute the
            // size. Safe to cast as we throw an exception if we are longer than 4077 bytes anyway.
            val sourceLen = source.peek().readAll(blackholeSink()).toInt()
            val padding = 128 - (sourceLen % 128)
            Buffer().apply {
                writeShort(padding)
                for (i in 0 until padding) {
                    writeByte(0)
                }
            }.also { paddingBytes = it }
        }
        return if (paddingBytes.exhausted()) {
            source.read(sink, byteCount)
        } else {
            paddingBytes.read(sink, byteCount)
        }
    }

    override fun close() {
        source.close()
    }

    override fun timeout(): Timeout {
        return source.timeout()
    }
}
