package me.tatarka.webpush

import okio.Buffer
import okio.BufferedSource
import okio.ByteString
import okio.ByteString.Companion.toByteString
import okio.IOException
import okio.Source
import okio.Timeout
import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECKey
import java.security.interfaces.ECPublicKey
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

typealias Headers = Iterable<Pair<String, String>>

open class WebPushFormatException(message: String) : Exception(message)

/**
 * Represents an encrypted WebPush payload with associated headers. You can use [WebPush.encrypt] to
 * encrypt a payload and [WebPush.decrypt] to decrypt it.
 *
 * @constructor Constructs a WebPush from the provided headers and encrypted payload.
 * @param headers A list of name,value-pair of headers. Note: these will not be validated they are
 * correct until [decrypt] is called.
 * @param encryptedBody The encrypted payload of the WebPush.
 */
class WebPush(
    val headers: Headers,
    val encryptedBody: Source,
) {

    /**
     * Decrypts the encrypted WebPush body using the given [authSecret] and [keys].
     *
     * @param authSecret The auth secret. Must be 16 bytes or an [IllegalArgumentException] will be
     * thrown.
     * @param keys The public/private key pair used for decryption. This must use Elliptic Curve
     * P-256 or an [IllegalArgumentException] will be thrown.
     * @return The decrypted body.
     *
     * @throws IllegalArgumentException if authSecret or keys are of the wrong type.
     * @throws WebPushFormatException if the web push format is invalid.
     * @throws GeneralSecurityException if decryption fails or if the decrypted payload is invalid.
     */
    @Throws(WebPushFormatException::class, GeneralSecurityException::class)
    fun decrypt(
        authSecret: ByteString,
        keys: KeyPair,
    ): Source {
        val publicKey = keys.public
        val privateKey = keys.private
        checkParams(authSecret, publicKey, privateKey)

        return when (ContentEncoding.match(headers)) {
            ContentEncoding.aes128gcm -> {
                aes128gcmDecrypt(
                    authSecret = authSecret,
                    publicKey = publicKey,
                    privateKey = privateKey,
                    encryptedBody = encryptedBody
                )
            }

            ContentEncoding.aesgcm -> {
                aesgcmDecrypt(
                    authSecret = authSecret,
                    publicKey = publicKey,
                    privateKey = privateKey,
                    headers = headers,
                    encryptedBody = encryptedBody,
                )
            }
        }
    }

    /**
     * The Content-Encoding used to encrypt/decrypt the WebPush.
     */
    enum class ContentEncoding {
        /**
         * The 'aes128gcm' content encoding as specified in the
         * [RFC](https://datatracker.ietf.org/doc/html/rfc8291).
         */
        aes128gcm {
            override fun toString(): String = "aes128gcm"
        },

        /**
         * The 'aesgcm' content encoding as specified in the
         * [draft RFC](https://datatracker.ietf.org/doc/html/draft-ietf-webpush-encryption-04).
         */
        aesgcm {
            override fun toString(): String = "aesgcm"
        };

        companion object {
            /**
             * Obtains a [ContentEncoding] from the given string value which can be 'aes128gcm' or 'aesgcm'.
             * @throws WebPushFormatException if the value is an unsupported encoding
             */
            fun of(value: String): ContentEncoding {
                return when (value) {
                    "aes128gcm" -> aes128gcm
                    "aesgcm" -> aesgcm
                    else -> throw WebPushFormatException("Unsupported Content-Encoding: $value")
                }
            }

            /**
             * Obtains a [ContentEncoding] by looking for a 'Content-Encoding' header.
             * @throws WebPushFormatException if the header is missing or has an unsupported encoding.
             */
            internal fun match(headers: Headers): ContentEncoding {
                for ((name, value) in headers) {
                    when (name) {
                        "Content-Encoding" -> {
                            return of(value)
                        }
                    }
                }
                throw WebPushFormatException("Missing 'Content-Encoding' header")
            }
        }
    }

    companion object {
        const val HeaderContentEncoding = "Content-Encoding"
        const val HeaderCryptoKey = "Crypto-Key"
        const val HeaderEncryption = "Encryption"

        @Suppress("NOTHING_TO_INLINE")
        @OptIn(ExperimentalContracts::class)
        private inline fun checkParams(
            authSecret: ByteString,
            publicKey: PublicKey,
            privateKey: PrivateKey
        ) {
            contract {
                returns() implies (publicKey is ECPublicKey)
                returns() implies (privateKey is ECKey)
            }
            if (authSecret.size != 16) {
                throw IllegalArgumentException("authSecret must by 16 bytes")
            }
            if (privateKey !is ECKey) {
                throw IllegalArgumentException("keys must use the Elliptic Curve algorithm")
            }
            if (publicKey !is ECPublicKey) {
                throw IllegalArgumentException("keys must use the Elliptic Curve algorithm")
            }
            if (!isP256EcParameterSpec(publicKey.params)) {
                throw IllegalArgumentException("keys must use Curve P-256")
            }
        }


        /**
         * Constructs a WebPush by encrypting the given body. The returned object will include both
         * the encrypted body and necessary headers for decryption.
         *
         * @param authSecret The auth secret. Must be 16 bytes or an [IllegalArgumentException] will be
         * thrown.
         * @param keys The public/private key pair used for encryption. This must use Elliptic Curve
         * P-256 or an [IllegalArgumentException] will be thrown.
         * @param clientPublicKey The public key of the client that will decrypt the WebPush.
         * @param body The body to encrypt. This body must fit within the default payload size
         * which allows 4077 bytes of cleartext, otherwise an exception will be thrown when
         * encrypting the body.
         * @param encoding The content encoding to use. The default is 'aes128gcm', but 'aesgcm'
         * from the draft RFC may also be used.
         *
         * @throws IllegalArgumentException if authSecret or keys are of the wrong type.
         * @throws GeneralSecurityException if encryption fails.
         */
        @JvmStatic
        @JvmOverloads
        @Throws(WebPushFormatException::class, GeneralSecurityException::class)
        fun encrypt(
            authSecret: ByteString,
            keys: KeyPair,
            clientPublicKey: ByteString,
            body: BufferedSource,
            encoding: ContentEncoding = ContentEncoding.aes128gcm,
        ): WebPush {
            return encrypt(
                authSecret,
                keys,
                clientPublicKey,
                body,
                encoding,
                salt = ByteArray(16).apply {
                    SecureRandom().nextBytes(this)
                }.toByteString(),
                paddingStrategy = PaddingStrategy.MultipleOf128,
            )
        }

        /**
         * Internal impl of encrypt that can be used for testing, without exposing these additional
         * params to the client for security.
         *
         * @param salt The salt to encrypt with. Must be unique per message. The default impl
         * generates a random salt.
         * @param padSource Function to add padding to the body before encoding. The default impl
         * pads to multiple of 128 bytes.
         */
        internal fun encrypt(
            authSecret: ByteString,
            keys: KeyPair,
            clientPublicKey: ByteString,
            body: BufferedSource,
            encoding: ContentEncoding,
            salt: ByteString,
            paddingStrategy: PaddingStrategy,
        ): WebPush {
            val publicKey = keys.public
            val privateKey = keys.private
            checkParams(authSecret, publicKey, privateKey)

            return when (encoding) {
                ContentEncoding.aes128gcm -> {
                    aes128gcmEncrypt(
                        authSecret = authSecret,
                        publicKey = publicKey,
                        privateKey = privateKey,
                        clientPublicKey = clientPublicKey,
                        body = body,
                        salt = salt,
                        paddingStrategy = paddingStrategy,
                    )
                }

                ContentEncoding.aesgcm -> {
                    aesgcmEncrypt(
                        authSecret = authSecret,
                        publicKey = publicKey,
                        privateKey = privateKey,
                        clientPublicKey = clientPublicKey,
                        body = body,
                        salt = salt,
                        paddingStrategy = paddingStrategy
                    )
                }
            }
        }

        /**
         * Generates a random 16 byte authSecret.
         */
        @JvmStatic
        fun generateAuthSecret(): ByteString {
            return ByteArray(16).apply {
                SecureRandom().nextBytes(this)
            }.toByteString()
        }

        /**
         * Encodes the given public key.
         */
        @JvmStatic
        @Throws(GeneralSecurityException::class)
        fun encodePublicKey(key: ECPublicKey): ByteString {
            return pointEncode(key.w).toByteString()
        }
    }
}

internal class SizeRestrictedSource(private val size: Int, private val source: Source) : Source {
    private var bytesRead = 0L

    override fun read(sink: Buffer, byteCount: Long): Long {
        val newBytesRead = source.read(sink, byteCount)
        if (newBytesRead == -1L) return -1
        bytesRead += newBytesRead
        if (bytesRead > size) {
            throw IOException("Body is longer than $size bytes")
        }
        return newBytesRead
    }

    override fun close() {
        source.close()
    }

    override fun timeout(): Timeout {
        return source.timeout()
    }
}

/**
 * How to pad the plain text, really only used internally so we can run tests with 0 padding.
 */
internal enum class PaddingStrategy {
    Zero,
    MultipleOf128
}

internal const val PAYLOAD_BOCK_SIZE = 4096