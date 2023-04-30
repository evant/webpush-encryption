# webpush-encryption

A lightweight webpush encryption/decryption library for kotlin/android

This library supports both the 'aes128gcm' content encoding as specified in the
[WebPush encryption RFC](https://datatracker.ietf.org/doc/html/rfc8291) as well as the legacy 'aesgcm' encoding as
defined in the [draft RFC](https://datatracker.ietf.org/doc/html/draft-ietf-webpush-encryption-04).

It is built with [okio](https://square.github.io/okio/) and exposes types as `ByteString` and `Source`. These can easily
be converted to and from other forms using the built-in functions on those types.

## Download

```kotlin
implemenation("me.tatarka.webpush:webpush-encryption:0.1")
```

## Usage

### Encryption

To encrypt, construct a WebPush object by calling `WebPush.encrypt()`.

```kotlin
val webPush = WebPush.encrypt(
    authSecret = authSecret,
    keys = keys,
    body = body,
    encoding = ContentEncoding.aes128gcm // or ContentEncoding.aesgcm
)
```

where:

- `authSecret` is the 16-byte shared auth secret.
- `keys` is the server public/private key pair, which must be a p-256 elliptic curve (See later section on how to
  generate).
- `body` is the plaintext payload to encrypt.

You can then pass along the returned WebPush with the server of your choice. It includes `headers` and
the `encryptedBody`.

### Decryption

To decrypt, construct a WebPush object using its constructor then call `webPush.decrypt()`.

```kotlin
val webPush = WebPush(headers = headers, encryptedBody = encrypedBody)
val bodyPlainText = webPush.decrypt(
    authSecret = authSecret,
    keys = keys
)
```

where:

- `authSecret` is the 16-byte shared auth secret.
- `keys` is the client public/private key pair, which must be a p-256 elliptic curve (See later section on how to
  generate).

### Generating And Sharing Keys

#### Auth Secret

The auth secret is a random set of 16 bytes. You may use the convenience method `WebPush.generateAuthSecret()` or
generate them yourself. Note: It's recommended to use a secure random number generator.

#### Public/Private Key Pair

Both the server and the client need to generate a P-256 elliptic curve key pair. You can do this on the jvm with:

```kotlin
val keyPair = KeyPairGenerator.getInstance("EC").apply {
    initialize(ECGenParameterSpec("secp256r1"))
}.generateKeyPair()
```

or on Android storing in the AndroidKeyStore (min api 31) with:

```kotlin
val keyPair = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
    .apply {
        initialize(
            KeyGenParameterSpec.Builder(KeyAlias, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .build()
        )
    }.generateKeyPair()
```

#### Sharing

You will likely want share the auth secret and public key from the client to the server. To accomplish this you may want
to base64-url-encode them. You can do this with:

```kotlin
val authSecretBase64 = authSecret.base64Url()
val publicKeyBase64 = WebPush.encodePublicKey(publicKey).base64Url()
```

### Limitations

Only 1 record of the default size of 4096 bytes is currently supported. A plaintext payload of more than 3993 bytes
using 'aes128gcm' (or 4077 bytes using 'aesgcm') will be rejected.