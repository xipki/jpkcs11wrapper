// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package org.xipki.pkcs11.parameters;

import org.xipki.pkcs11.Functions;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This abstract class encapsulates parameters for the DH mechanisms
 * Mechanism.ECDH1_DERIVE, Mechanism.ECDH1_COFACTOR_DERIVE,
 * Mechanism.ECMQV_DERIVE, Mechanism.X9_42_DH_DERIVE ,
 * Mechanism.X9_42_DH_HYBRID_DERIVE and Mechanism.X9_42_MQV_DERIVE.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
abstract public class DHKeyDerivationParameters implements Parameters {

  /**
   * The key derivation function used on the shared secret value.
   */
  protected long kdf;

  /**
   * The other party's public key value.
   */
  protected byte[] publicData;

  /**
   * Create a new DHKeyDerivationParameters object with the given attributes.
   *
   * @param kdf
   *          The key derivation function used on the shared secret value.
   *          One of the values defined in CKD_
   * @param publicData
   *          The other party's public key value.
   */
  protected DHKeyDerivationParameters(long kdf, byte[] publicData) {
    setPublicData(publicData);
    setKeyDerivationFunction(kdf);
  }

  /**
   * Get the key derivation function used on the shared secret value.
   *
   * @return The key derivation function used on the shared secret value.
   *         One of the values defined in CKD_
   */
  public long getKeyDerivationFunction() {
    return kdf;
  }

  /**
   * Get the other party's public key value.
   *
   * @return The other party's public key value.
   */
  public byte[] getPublicData() {
    return publicData;
  }

  /**
   * Set the key derivation function used on the shared secret value.
   *
   * @param kdf
   *          The key derivation function used on the shared secret value.
   *          One of the values defined in CKD_
   */
  public void setKeyDerivationFunction(long kdf) {
    if ((kdf != CKD_NULL) && (kdf != CKD_SHA1_KDF)
        && (kdf != CKD_SHA1_KDF_ASN1) && (kdf != CKD_SHA1_KDF_CONCATENATE)) {
      throw new IllegalArgumentException("Illegal value for argument 'kdf': " + Functions.ckdCodeToName(kdf));
    }
    this.kdf = kdf;
  }

  /**
   * Set the other party's public key value.
   *
   * @param publicData
   *          The other party's public key value.
   */
  public void setPublicData(byte[] publicData) {
    this.publicData = Functions.requireNonNull("publicData", publicData);
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "  Key Derivation Function: " + Functions.ckdCodeToName(kdf) +
        "\n  Public Data: " + Functions.toHex(publicData);
  }

}
