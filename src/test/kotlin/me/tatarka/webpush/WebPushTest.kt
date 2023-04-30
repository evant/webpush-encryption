package me.tatarka.webpush

import assertk.assertAll
import assertk.assertThat
import assertk.assertions.contains
import assertk.assertions.containsExactlyInAnyOrder
import assertk.assertions.isEqualTo
import assertk.assertions.isFailure
import assertk.assertions.isInstanceOf
import assertk.assertions.isNotNull
import assertk.assertions.isSuccess
import assertk.assertions.message
import assertk.assertions.messageContains
import assertk.tableOf
import okio.Buffer
import okio.ByteString.Companion.decodeBase64
import okio.IOException
import okio.buffer
import org.junit.Test
import kotlin.random.Random

class WebPushTest {
    @Test
    fun fails_with_missing_content_encoding() {
        assertThat {
            WebPush(
                headers = listOf(),
                encryptedBody = Buffer()
            ).decrypt(
                authSecret = generateAuthSecret(),
                keys = generateKeyPair(),
            )
        }.isFailure()
            .isInstanceOf(WebPushFormatException::class)
            .messageContains("Content-Encoding")
    }

    @Test
    fun fails_with_invalid_content_encoding() {
        assertThat {
            WebPush(
                headers = listOf("Content-Encoding" to "bad"),
                encryptedBody = Buffer()
            ).decrypt(
                authSecret = generateAuthSecret(),
                keys = generateKeyPair(),
            )
        }.isFailure()
            .isInstanceOf(WebPushFormatException::class)
    }

    @Test
    fun fails_with_missing_crypto_key() {
        assertThat {
            WebPush(
                headers = listOf("Content-Encoding" to "aesgcm"),
                encryptedBody = Buffer()
            ).decrypt(
                authSecret = generateAuthSecret(),
                keys = generateKeyPair(),
            )
        }.isFailure()
            .isInstanceOf(WebPushFormatException::class)
        assertThat {
            WebPush(
                headers = listOf(
                    "Content-Encoding" to "aesgcm",
                    "Crypto-Key" to "bad"
                ),
                encryptedBody = Buffer()
            ).decrypt(
                authSecret = generateAuthSecret(),
                keys = generateKeyPair(),
            )
        }.isFailure()
            .isInstanceOf(WebPushFormatException::class)
            .messageContains("Crypto-Key")
    }

    @Test
    fun fails_with_invalid_crypto_key() {
        assertThat {
            WebPush(
                headers = listOf(
                    "Content-Encoding" to "aesgcm",
                    "Crypto-Key" to "bad"
                ),
                encryptedBody = Buffer()
            ).decrypt(
                authSecret = generateAuthSecret(),
                keys = generateKeyPair(),
            )
        }.isFailure()
            .isInstanceOf(WebPushFormatException::class)
            .messageContains("Crypto-Key")
    }

    @Test
    fun fails_with_missing_encryption() {
        assertThat {
            WebPush(
                headers = listOf(
                    "Content-Encoding" to "aesgcm",
                    "Crypto-Key" to "dh=YQ"
                ),
                encryptedBody = Buffer()
            ).decrypt(
                authSecret = generateAuthSecret(),
                keys = generateKeyPair(),
            )
        }.isFailure()
            .isInstanceOf(WebPushFormatException::class)
            .messageContains("Encryption")
    }

    @Test
    fun fails_with_invalid_encryption() {
        assertThat {
            WebPush(
                headers = listOf(
                    "Content-Encoding" to "aesgcm",
                    "Crypto-Key" to "dh=YQ",
                    "Encryption" to "bad"
                ),
                encryptedBody = Buffer()
            ).decrypt(
                authSecret = generateAuthSecret(),
                keys = generateKeyPair(),
            )
        }.isFailure()
            .isInstanceOf(WebPushFormatException::class)
            .messageContains("Encryption")
    }

    @Test
    fun fails_with_auth_secret_of_wrong_size() {
        assertThat {
            WebPush(
                headers = listOf(
                    "Content-Encoding" to "aesgcm",
                    "Crypto-Key" to "dh=BNoRDbb84JGm8g5Z5CFxurSqsXWJ11ItfXEWYVLE85Y7CYkDjXsIEc4aqxYaQ1G8BqkXCJ6DPpDrWtdWj_mugHU",
                    "Encryption" to "salt=lngarbyKfMoi9Z75xYXmkg"
                ),
                encryptedBody = Buffer().write("6nqAQUME8hNqw5J3kl8cpVVJylXKYqZOeseZG8UueKpA".decodeBase64()!!)
            ).decrypt(
                authSecret = "R29vIGdvbyBn".decodeBase64()!!,
                keys = generateKeyPair(),
            )
        }.isFailure()
            .isInstanceOf(IllegalArgumentException::class)
            .message().isNotNull().contains("authSecret", "16")
    }

    @Test
    fun fails_with_key_of_wrong_algorithm() {
        assertThat {
            WebPush(
                headers = listOf(
                    "Content-Encoding" to "aesgcm",
                    "Crypto-Key" to "dh=BNoRDbb84JGm8g5Z5CFxurSqsXWJ11ItfXEWYVLE85Y7CYkDjXsIEc4aqxYaQ1G8BqkXCJ6DPpDrWtdWj_mugHU",
                    "Encryption" to "salt=lngarbyKfMoi9Z75xYXmkg"
                ),
                encryptedBody = Buffer().write("6nqAQUME8hNqw5J3kl8cpVVJylXKYqZOeseZG8UueKpA".decodeBase64()!!)
            ).decrypt(
                authSecret = "R29vIGdvbyBnJyBqb29iIQ".decodeBase64()!!,
                keys = generateKeyPairWithWrongAlgorithm(),
            )
        }.isFailure()
            .isInstanceOf(IllegalArgumentException::class)
            .message().isNotNull().contains("keys", "Elliptic Curve")
    }

    @Test
    fun fails_with_key_of_wrong_curve() {
        assertThat {
            WebPush(
                headers = listOf(
                    "Content-Encoding" to "aesgcm",
                    "Crypto-Key" to "dh=BNoRDbb84JGm8g5Z5CFxurSqsXWJ11ItfXEWYVLE85Y7CYkDjXsIEc4aqxYaQ1G8BqkXCJ6DPpDrWtdWj_mugHU",
                    "Encryption" to "salt=lngarbyKfMoi9Z75xYXmkg"
                ),
                encryptedBody = Buffer().write("6nqAQUME8hNqw5J3kl8cpVVJylXKYqZOeseZG8UueKpA".decodeBase64()!!)
            ).decrypt(
                authSecret = "R29vIGdvbyBnJyBqb29iIQ".decodeBase64()!!,
                keys = generateKeyPairWithWrongCurve(),
            )
        }.isFailure()
            .isInstanceOf(IllegalArgumentException::class)
            .message().isNotNull().contains("keys", "P-256")
    }

    @Test
    fun fails_encryption_if_body_is_too_long() {
        tableOf("encoding", "length")
            .row(WebPush.ContentEncoding.aesgcm, 4077)
            .row(WebPush.ContentEncoding.aes128gcm, 3993)
            .forAll { encoding, length ->
                val longBody = Buffer()
                for (i in 0 until 4078) {
                    longBody.writeByte(Random.nextBytes(1)[0].toInt())
                }

                assertThat {
                    val webPush = WebPush.encrypt(
                        authSecret = "R29vIGdvbyBnJyBqb29iIQ".decodeBase64()!!,
                        clientPublicKey = "BCEkBjzL8Z3C-oi2Q7oE5t2Np-p7osjGLg93qUP0wvqRT21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQU".decodeBase64()!!,
                        keys = keyPair(
                            publicKey = "BNoRDbb84JGm8g5Z5CFxurSqsXWJ11ItfXEWYVLE85Y7CYkDjXsIEc4aqxYaQ1G8BqkXCJ6DPpDrWtdWj_mugHU",
                            privateKey = "nCScek-QpEjmOOlT-rQ38nZzvdPlqa00Zy0i6m2OJvY"
                        ),
                        body = longBody,
                        encoding = encoding
                    )
                    // Need to actually read the body to trigger.
                    webPush.encryptedBody.buffer().readByteString()
                }.isFailure()
                    .isInstanceOf(IOException::class)
                    .message().isNotNull().contains("Body is longer than", length.toString())

            }
    }

    @Test
    fun fails_decryption_if_body_is_too_short() {
        assertThat {
            WebPush(
                headers = listOf(
                    "Content-Encoding" to "aesgcm",
                    "Crypto-Key" to "dh=BNoRDbb84JGm8g5Z5CFxurSqsXWJ11ItfXEWYVLE85Y7CYkDjXsIEc4aqxYaQ1G8BqkXCJ6DPpDrWtdWj_mugHU",
                    "Encryption" to "salt=lngarbyKfMoi9Z75xYXmkg"
                ),
                encryptedBody = Buffer().write("6nqAQUME8hNqw5J3kl8cpVVJylXKYqZOeseZG8UueKpA".decodeBase64()!!)
            ).decrypt(
                authSecret = "R29vIGdvbyBnJyBqb29iIQ".decodeBase64()!!,
                keys = keyPair(
                    publicKey = "BCEkBjzL8Z3C-oi2Q7oE5t2Np-p7osjGLg93qUP0wvqRT21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQU",
                    privateKey = "9FWl15_QUQAWDaD3k3l50ZBZQJ4au27F1V4F0uLSD_M",
                ),
            ).buffer().use { it.readUtf8() }
        }.isSuccess()
            .isEqualTo("I am the walrus")
    }

    @Test
    fun encrypts_body_aesgcm() {
        val webPush = WebPush.encrypt(
            authSecret = "R29vIGdvbyBnJyBqb29iIQ".decodeBase64()!!,
            clientPublicKey = "BCEkBjzL8Z3C-oi2Q7oE5t2Np-p7osjGLg93qUP0wvqRT21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQU".decodeBase64()!!,
            keys = keyPair(
                publicKey = "BNoRDbb84JGm8g5Z5CFxurSqsXWJ11ItfXEWYVLE85Y7CYkDjXsIEc4aqxYaQ1G8BqkXCJ6DPpDrWtdWj_mugHU",
                privateKey = "nCScek-QpEjmOOlT-rQ38nZzvdPlqa00Zy0i6m2OJvY"
            ),
            body = Buffer().writeUtf8("I am the walrus"),
            encoding = WebPush.ContentEncoding.aesgcm,
            salt = "lngarbyKfMoi9Z75xYXmkg".decodeBase64()!!,
            paddingStrategy = PaddingStrategy.Zero,
        )

        assertAll {
            assertThat(webPush.headers).containsExactlyInAnyOrder(
                "Content-Encoding" to "aesgcm",
                "Crypto-Key" to "dh=BNoRDbb84JGm8g5Z5CFxurSqsXWJ11ItfXEWYVLE85Y7CYkDjXsIEc4aqxYaQ1G8BqkXCJ6DPpDrWtdWj_mugHU",
                "Encryption" to "salt=lngarbyKfMoi9Z75xYXmkg",
            )
            assertThat {
                webPush.encryptedBody.buffer().readByteString().base64Url()
            }.isSuccess()
                .isEqualTo("6nqAQUME8hNqw5J3kl8cpVVJylXKYqZOeseZG8UueKpA")
        }
    }

    @Test
    fun decrypts_body_aesgcm() {
        assertThat {
            WebPush(
                headers = listOf(
                    "Content-Encoding" to "aesgcm",
                    "Crypto-Key" to "dh=BNoRDbb84JGm8g5Z5CFxurSqsXWJ11ItfXEWYVLE85Y7CYkDjXsIEc4aqxYaQ1G8BqkXCJ6DPpDrWtdWj_mugHU",
                    "Encryption" to "salt=lngarbyKfMoi9Z75xYXmkg"
                ),
                encryptedBody = Buffer().write("6nqAQUME8hNqw5J3kl8cpVVJylXKYqZOeseZG8UueKpA".decodeBase64()!!)
            ).decrypt(
                authSecret = "R29vIGdvbyBnJyBqb29iIQ".decodeBase64()!!,
                keys = keyPair(
                    publicKey = "BCEkBjzL8Z3C-oi2Q7oE5t2Np-p7osjGLg93qUP0wvqRT21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQU",
                    privateKey = "9FWl15_QUQAWDaD3k3l50ZBZQJ4au27F1V4F0uLSD_M",
                ),
            ).buffer().use { it.readUtf8() }
        }.isSuccess()
            .isEqualTo("I am the walrus")
    }

    @Test
    fun round_trips_aesgcm() {
        assertThat {
            val authSecret = "R29vIGdvbyBnJyBqb29iIQ".decodeBase64()!!
            val webPush = WebPush.encrypt(
                authSecret = authSecret,
                clientPublicKey = "BCEkBjzL8Z3C-oi2Q7oE5t2Np-p7osjGLg93qUP0wvqRT21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQU".decodeBase64()!!,
                keys = keyPair(
                    publicKey = "BNoRDbb84JGm8g5Z5CFxurSqsXWJ11ItfXEWYVLE85Y7CYkDjXsIEc4aqxYaQ1G8BqkXCJ6DPpDrWtdWj_mugHU",
                    privateKey = "nCScek-QpEjmOOlT-rQ38nZzvdPlqa00Zy0i6m2OJvY"
                ),
                body = Buffer().writeUtf8("I am the walrus"),
                encoding = WebPush.ContentEncoding.aesgcm,
            )
            webPush.decrypt(
                authSecret = authSecret,
                keys = keyPair(
                    publicKey = "BCEkBjzL8Z3C-oi2Q7oE5t2Np-p7osjGLg93qUP0wvqRT21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQU",
                    privateKey = "9FWl15_QUQAWDaD3k3l50ZBZQJ4au27F1V4F0uLSD_M",
                ),
            ).buffer().use { it.readUtf8() }
        }.isSuccess()
            .isEqualTo("I am the walrus")
    }

    @Test
    fun encrypts_body_aes128gcm() {
        val webPush = WebPush.encrypt(
            authSecret = "BTBZMqHH6r4Tts7J_aSIgg".decodeBase64()!!,
            clientPublicKey = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4".decodeBase64()!!,
            keys = keyPair(
                publicKey = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
                privateKey = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
            ),
            body = Buffer().writeUtf8("When I grow up, I want to be a watermelon"),
            encoding = WebPush.ContentEncoding.aes128gcm,
            salt = "DGv6ra1nlYgDCS1FRnbzlw".decodeBase64()!!,
            paddingStrategy = PaddingStrategy.Zero,
        )

        assertAll {
            assertThat(webPush.headers).containsExactlyInAnyOrder(
                "Content-Encoding" to "aes128gcm",
            )
            assertThat {
                webPush.encryptedBody.buffer().readByteString().base64Url()
            }.isSuccess()
                .isEqualTo("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")
        }
    }

    @Test
    fun decrypts_body_aes128gcm() {
        assertThat {
            WebPush(
                headers = listOf(
                    "Content-Encoding" to "aes128gcm",
                ),
                encryptedBody = Buffer().write("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN".decodeBase64()!!)
            ).decrypt(
                authSecret = "BTBZMqHH6r4Tts7J_aSIgg".decodeBase64()!!,
                keys = keyPair(
                    publicKey = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
                    privateKey = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94",
                ),
            ).buffer().use { it.readUtf8() }
        }.isSuccess()
            .isEqualTo("When I grow up, I want to be a watermelon")
    }

    @Test
    fun round_trips_aes128gcm() {
        assertThat {
            val authSecret = "BTBZMqHH6r4Tts7J_aSIgg".decodeBase64()!!
            val webPush = WebPush.encrypt(
                authSecret = authSecret,
                clientPublicKey = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4".decodeBase64()!!,
                keys = keyPair(
                    publicKey = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
                    privateKey = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
                ),
                body = Buffer().writeUtf8("When I grow up, I want to be a watermelon"),
                encoding = WebPush.ContentEncoding.aes128gcm,
            )
            webPush.decrypt(
                authSecret = authSecret,
                keys = keyPair(
                    publicKey = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
                    privateKey = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94",
                ),
            ).buffer().use { it.readUtf8() }
        }.isSuccess()
            .isEqualTo("When I grow up, I want to be a watermelon")
    }
}
