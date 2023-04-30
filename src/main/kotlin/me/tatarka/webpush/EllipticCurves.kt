// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

/**
 * Utility functions and enums for elliptic curve crypto, used in ECDSA and ECDH.
 */
package me.tatarka.webpush

import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.Key
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.interfaces.ECKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.EllipticCurve
import java.util.Arrays
import javax.crypto.KeyAgreement

/**
 * Returns the size of an element of the field over which the curve is defined.
 *
 * @param curve must be a prime order elliptic curve
 * @return the size of an element in bits
 */
private fun fieldSizeInBits(curve: EllipticCurve): Int {
    return getModulus(curve).subtract(BigInteger.ONE).bitLength()
}

/**
 * Returns the size of an element of the field over which the curve is defined.
 *
 * @param curve must be a prime order elliptic curve
 * @return the size of an element in bytes.
 */
private fun fieldSizeInBytes(curve: EllipticCurve): Int {
    return (fieldSizeInBits(curve) + 7) / 8
}

/**
 * Computes a square root modulo an odd prime. Timing and exceptions can leak information about
 * the inputs. Therefore this method must only be used to decompress public keys.
 *
 * @param x the square
 * @param p the prime modulus (the behaviour of the method is undefined if p is not prime).
 * @return a value s such that s^2 mod p == x mod p
 * @throws GeneralSecurityException if the square root could not be found.
 */
private fun modSqrt(x: BigInteger, p: BigInteger): BigInteger {
    var x = x
    if (p.signum() != 1) {
        throw InvalidAlgorithmParameterException("p must be positive")
    }
    x = x.mod(p)
    var squareRoot: BigInteger? = null
    // Special case for x == 0.
    // This check is necessary for Cipolla's algorithm.
    if (x == BigInteger.ZERO) {
        return BigInteger.ZERO
    }
    if (p.testBit(0) && p.testBit(1)) {
        // Case p % 4 == 3
        // q = (p + 1) / 4
        val q = p.add(BigInteger.ONE).shiftRight(2)
        squareRoot = x.modPow(q, p)
    } else if (p.testBit(0) && !p.testBit(1)) {
        // Case p % 4 == 1
        // For this case we use Cipolla's algorithm.
        // This alogorithm is preferrable to Tonelli-Shanks for primes p where p-1 is divisible by
        // a large power of 2, which is a frequent choice since it simplifies modular reduction.
        var a = BigInteger.ONE
        var d: BigInteger? = null
        val q1 = p.subtract(BigInteger.ONE).shiftRight(1)
        var tries = 0
        while (true) {
            d = a.multiply(a).subtract(x).mod(p)
            // Special case d==0. We need d!=0 below.
            if (d == BigInteger.ZERO) {
                return a
            }
            // Computes the Legendre symbol. Using the Jacobi symbol would be a faster.
            val t = d.modPow(q1, p)
            a = if (t.add(BigInteger.ONE) == p) {
                // d is a quadratic non-residue.
                break
            } else if (t != BigInteger.ONE) {
                // p does not divide d. Hence, t != 1 implies that p is not a prime.
                throw InvalidAlgorithmParameterException("p is not prime")
            } else {
                a.add(BigInteger.ONE)
            }
            tries++
            // If 128 tries were not enough to find a quadratic non-residue, then it is likely that
            // p is not prime. To avoid an infinite loop in this case we perform a primality test.
            // If p is prime then this test will be done with a negligible probability of 2^{-128}.
            if (tries == 128) {
                if (!p.isProbablePrime(80)) {
                    throw InvalidAlgorithmParameterException("p is not prime")
                }
            }
        }
        // Since d = a^2 - x is a quadratic non-residue modulo p, we have
        //   a - sqrt(d) == (a + sqrt(d))^p (mod p),
        // and hence
        //   x == (a + sqrt(d))(a - sqrt(d)) == (a + sqrt(d))^(p+1) (mod p).
        // Thus if x is square then (a + sqrt(d))^((p+1)/2) (mod p) is a square root of x.
        val q = p.add(BigInteger.ONE).shiftRight(1)
        var u = a
        var v = BigInteger.ONE
        for (bit in q.bitLength() - 2 downTo 0) {
            // Square u + v sqrt(d) and reduce mod p.
            var tmp = u.multiply(v)
            u = u.multiply(u).add(v.multiply(v).mod(p).multiply(d)).mod(p)
            v = tmp.add(tmp).mod(p)
            if (q.testBit(bit)) {
                // Multiply u + v sqrt(d) by a + sqrt(d) and reduce mod p.
                tmp = u.multiply(a).add(v.multiply(d)).mod(p)
                v = a.multiply(v).add(u).mod(p)
                u = tmp
            }
        }
        squareRoot = u
    }
    // The methods used to compute the square root only guarantees a correct result if the
    // preconditions (i.e. p prime and x is a square) are satisfied. Otherwise the value is
    // undefined. Hence it is important to verify that squareRoot is indeed a square root.
    if (squareRoot != null && squareRoot.multiply(squareRoot).mod(p).compareTo(x) != 0) {
        throw GeneralSecurityException("Could not find a modular square root")
    }
    return squareRoot!!
}

/**
 * Computes the y coordinate of a point on an elliptic curve. This method can be used to
 * decompress elliptic curve points.
 *
 * @param x     the x-coordinate of the point
 * @param lsb   the least significant bit of the y-coordinate of the point.
 * @param curve this must be an elliptic curve over a prime field using Weierstrass
 * representation.
 * @return the y coordinate.
 * @throws GeneralSecurityException if there is no point with coordinate x on the curve, or if
 * curve is not supported.
 */
private fun getY(x: BigInteger, lsb: Boolean, curve: EllipticCurve): BigInteger {
    val p = getModulus(curve)
    val a = curve.a
    val b = curve.b
    val rhs = x.multiply(x).add(a).multiply(x).add(b).mod(p)
    var y = modSqrt(rhs, p)
    if (lsb != y.testBit(0)) {
        y = p.subtract(y).mod(p)
    }
    return y
}

/**
 * Returns an [ECPublicKey] from `publicKey` that is a public key in point format
 * `pointFormat` on `curve`.
 */
internal fun getEcPublicKey(publicKey: ByteArray): ECPublicKey {
    val point = pointDecode(publicKey)
    val pubSpec = ECPublicKeySpec(point, nistP256Params)
    val kf = KeyFactory.getInstance("EC")
    return kf.generatePublic(pubSpec) as ECPublicKey
}

/**
 * Returns an `ECPrivateKey` from `curve` type and `keyValue`.
 */
internal fun getEcPrivateKey(keyValue: ByteArray): PrivateKey {
    val privValue = fromUnsignedBigEndianBytes(keyValue)
    val spec = ECPrivateKeySpec(privValue, nistP256Params)
    val kf = KeyFactory.getInstance("EC")
    return kf.generatePrivate(spec)
}

/**
 * Decodes an encoded point on an elliptic curve. This method checks that the encoded point is on
 * the curve.
 *
 * @param encoded the encoded point
 * @return the point
 * @throws GeneralSecurityException if the encoded point is invalid or if the curve or format are
 * not supported.
 * @since 1.1.0
 */
internal fun pointDecode(encoded: ByteArray): ECPoint {
    val curve = nistP256Params.curve
    val coordinateSize = fieldSizeInBytes(curve)
    if (encoded.size != 2 * coordinateSize + 1) {
        throw GeneralSecurityException("invalid point size")
    }
    if (encoded[0].toInt() != 4) {
        throw GeneralSecurityException("invalid point format")
    }
    val x = BigInteger(1, encoded.copyOfRange(1, coordinateSize + 1))
    val y = BigInteger(1, encoded.copyOfRange(coordinateSize + 1, encoded.size))
    val point = ECPoint(x, y)
    checkPointOnCurve(point, curve)
    return point
}

/**
 * Encodes a point on an elliptic curve.
 *
 * @param point the point to encode
 * @return the encoded key exchange
 * @throws GeneralSecurityException if the point is not on the curve or if the format is not
 * supported.
 * @since 1.1.0
 */
internal fun pointEncode(point: ECPoint): ByteArray {
    val curve = nistP256Params.curve
    checkPointOnCurve(point, curve)
    val coordinateSize = fieldSizeInBytes(curve)
    val encoded = ByteArray(2 * coordinateSize + 1)
    val x = point.affineX.toBigEndianBytes()
    val y = point.affineY.toBigEndianBytes()
    // Order of System.arraycopy is important because x,y can have leading 0's.
    System.arraycopy(y, 0, encoded, 1 + 2 * coordinateSize - y.size, y.size)
    System.arraycopy(x, 0, encoded, 1 + coordinateSize - x.size, x.size)
    encoded[0] = 4
    return encoded
}

/**
 * Checks that the shared secret is on the curve of the private key, to prevent arithmetic errors
 * or fault attacks.
 */
private fun validateSharedSecret(secret: ByteArray, privateKey: ECKey) {
    val privateKeyCurve = privateKey.params.curve
    val x = BigInteger(1, secret)
    if (x.signum() == -1 || x >= getModulus(privateKeyCurve)) {
        throw GeneralSecurityException("shared secret is out of range")
    }
    // This will throw if x is not a valid coordinate.
    val _unused = getY(x, true /* lsb, doesn't matter here */, privateKeyCurve)
}

internal fun isP256EcParameterSpec(spec: ECParameterSpec): Boolean {
    return spec.curve == nistP256Params.curve && spec.generator == nistP256Params.generator &&
            spec.order == nistP256Params.order && spec.cofactor == nistP256Params.cofactor
}


/**
 * Generates the DH shared secret using `myPrivateKey` and `publicPoint`
 *
 * @since 1.1.0
 */
internal fun <K> computeSharedSecret(
    myPrivateKey: K,
    publicPoint: ECPoint
): ByteArray where K : Key, K : ECKey {
    checkPointOnCurve(publicPoint, myPrivateKey.params.curve)
    // Explicitly reconstruct the peer public key using private key's spec.
    val privSpec = myPrivateKey.params
    val publicKeySpec = ECPublicKeySpec(publicPoint, privSpec)
    val kf = KeyFactory.getInstance("EC")
    val publicKey = kf.generatePublic(publicKeySpec)
    val ka = KeyAgreement.getInstance("ECDH")
    ka.init(myPrivateKey)
    return try {
        ka.doPhase(publicKey, true /* lastPhase */)
        val secret = ka.generateSecret()
        validateSharedSecret(secret, myPrivateKey)
        secret
    } catch (ex: IllegalStateException) {
        // Due to CVE-2017-10176 some versions of OpenJDK might throw this unchecked exception,
        // converting it to a checked one to not crash the JVM. See also b/73760761.
        throw GeneralSecurityException(ex)
    }
}

private val nistP256Params = getNistCurveSpec(
    "115792089210356248762697446949407573530086143415290314195533631308867097853951",
    "115792089210356248762697446949407573529996955224135760342422259061068512044369",
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)

private fun getNistCurveSpec(
    decimalP: String,
    decimalN: String,
    hexB: String,
    hexGX: String,
    hexGY: String
): ECParameterSpec {
    val p = BigInteger(decimalP)
    val n = BigInteger(decimalN)
    val three = BigInteger("3")
    val a = p.subtract(three)
    val b = BigInteger(hexB, 16)
    val gx = BigInteger(hexGX, 16)
    val gy = BigInteger(hexGY, 16)
    val h = 1
    val fp = ECFieldFp(p)
    val curveSpec =
        EllipticCurve(fp, a, b)
    val g = ECPoint(gx, gy)
    return ECParameterSpec(curveSpec, g, n, h)
}

/**
 * Checks that a point is on a given elliptic curve.
 *
 *
 * This method implements the partial public key validation routine from Section 5.6.2.6 of [NIST SP
 * 800-56A](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf). A partial public key validation is sufficient for curves with cofactor 1. See
 * Section B.3 of http://www.nsa.gov/ia/_files/SuiteB_Implementer_G-113808.pdf.
 *
 *
 * The point validations above are taken from recommendations for ECDH, because parameter
 * checks in ECDH are much more important than for the case of ECDSA. Performing this test for
 * ECDSA keys is mainly a sanity check.
 *
 * @param point the point that needs verification
 * @param ec    the elliptic curve. This must be a curve over a prime order field.
 * @throws GeneralSecurityException if the field is binary or if the point is not on the curve.
 */
private fun checkPointOnCurve(point: ECPoint, ec: EllipticCurve) {
    val p = getModulus(ec)
    val x = point.affineX
    val y = point.affineY
    if (x == null || y == null) {
        throw GeneralSecurityException("point is at infinity")
    }
    // Check 0 <= x < p and 0 <= y < p.
    if (x.signum() == -1 || x >= p) {
        throw GeneralSecurityException("x is out of range")
    }
    if (y.signum() == -1 || y >= p) {
        throw GeneralSecurityException("y is out of range")
    }
    // Check y^2 == x^3 + a x + b (mod p)
    val lhs = y.multiply(y).mod(p)
    val rhs = x.multiply(x).add(ec.a).multiply(x).add(ec.b).mod(p)
    if (lhs != rhs) {
        throw GeneralSecurityException("Point is not on curve")
    }
}

/**
 * Returns the modulus of the field used by the curve specified in ecParams.
 *
 * @param curve must be a prime order elliptic curve
 * @return the order of the finite field over which curve is defined.
 */
private fun getModulus(curve: EllipticCurve): BigInteger {
    val field = curve.field
    return if (field is ECFieldFp) {
        field.p
    } else {
        throw GeneralSecurityException("Only curves over prime order fields are supported")
    }
}

/**
 * Encodes a non-negative [java.math.BigInteger] into the minimal two's-complement
 * representation in big-endian byte-order.
 *
 *
 * The most significant bit of the first byte is the sign bit, which is always 0 because the
 * input number is non-negative. Because of that, the output is at the same time also an unsigned
 * big-endian encoding that may have an additional zero byte at the beginning, and can be parsed
 * with [.fromUnsignedBigEndianBytes].
 */
private fun BigInteger.toBigEndianBytes(): ByteArray {
    require(signum() != -1) { "n must not be negative" }
    return toByteArray()
}

/**
 * Encodes a non-negative [java.math.BigInteger] into a byte array of a specified length,
 * using big-endian byte-order.
 *
 *
 * See also [RFC 8017, Sec. 4.2](https://www.rfc-editor.org/rfc/rfc8017#section-4.2)
 *
 *
 * throws a GeneralSecurityException if the number is negative or length is too short.
 */
private fun toBigEndianBytesOfFixedLength(n: BigInteger, length: Int): ByteArray {
    require(n.signum() != -1) { "integer must be nonnegative" }
    val b = n.toByteArray()
    if (b.size == length) {
        return b
    }
    if (b.size > length + 1 /* potential leading zero */) {
        throw GeneralSecurityException("integer too large")
    }
    if (b.size == length + 1) {
        return if (b[0].toInt() == 0 /* leading zero */) {
            Arrays.copyOfRange(b, 1, b.size)
        } else {
            throw GeneralSecurityException("integer too large")
        }
    }
    // Left zero pad b.
    val res = ByteArray(length)
    System.arraycopy(b, 0, res, length - b.size, b.size)
    return res
}

/**
 * Parses a [BigInteger] from a byte array using unsigned big-endian encoding.
 *
 *
 * See also [RFC 8017, Sec. 4.2](https://www.rfc-editor.org/rfc/rfc8017#section-4.2)
 */
private fun fromUnsignedBigEndianBytes(bytes: ByteArray): BigInteger {
    return BigInteger(1, bytes)
}
