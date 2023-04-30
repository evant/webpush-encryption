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
package me.tatarka.webpush

import java.security.GeneralSecurityException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * This function implements HMAC-based Extract-and-Expand Key Derivation Function (HKDF), as described
 * in [RFC 5869](https://tools.ietf.org/html/rfc5869).
 *
 * @param ikm the input keying material.
 * @param salt optional salt. A possibly non-secret random value. If no salt is provided (i.e. if
 * salt has length 0) then an array of 0s of the same size as the hash digest is used as salt.
 * @param info optional context and application specific information.
 * @param size The length of the generated pseudorandom string in bytes. The maximal size is
 * 255.DigestSize, where DigestSize is the size of the underlying HMAC.
 * @return size pseudorandom bytes.
 * @throws GeneralSecurityException if the `macAlgorithm` is not supported or if `size` is too large or if `salt` is not a valid key for macAlgorithm (which should not
 * happen since HMAC allows key sizes up to 2^64).
 */
internal fun computeHkdf(
    ikm: ByteArray?,
    salt: ByteArray?,
    info: ByteArray?,
    size: Int
): ByteArray {
    val macAlgorithm = "HmacSHA256"
    val mac = Mac.getInstance(macAlgorithm)
    if (size > 255 * mac.macLength) {
        throw GeneralSecurityException("size too large")
    }
    if (salt == null || salt.isEmpty()) {
        // According to RFC 5869, Section 2.2 the salt is optional. If no salt is provided
        // then HKDF uses a salt that is an array of zeros of the same length as the hash digest.
        mac.init(SecretKeySpec(ByteArray(mac.macLength), macAlgorithm))
    } else {
        mac.init(SecretKeySpec(salt, macAlgorithm))
    }
    val prk = mac.doFinal(ikm)
    val result = ByteArray(size)
    var ctr = 1
    var pos = 0
    mac.init(SecretKeySpec(prk, macAlgorithm))
    var digest = ByteArray(0)
    while (true) {
        mac.update(digest)
        mac.update(info)
        mac.update(ctr.toByte())
        digest = mac.doFinal()
        if (pos + digest.size < size) {
            System.arraycopy(digest, 0, result, pos, digest.size)
            pos += digest.size
            ctr++
        } else {
            System.arraycopy(digest, 0, result, pos, size - pos)
            break
        }
    }
    return result
}