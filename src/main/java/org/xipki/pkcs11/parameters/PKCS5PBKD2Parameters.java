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
import sun.security.pkcs11.wrapper.CK_PKCS5_PBKD2_PARAMS;

import static org.xipki.pkcs11.PKCS11Constants.CKP_PKCS5_PBKD2_HMAC_SHA1;
import static org.xipki.pkcs11.PKCS11Constants.CKZ_SALT_SPECIFIED;

/**
 * This class encapsulates parameters for the Mechanism.PKCS5_PKKD2 mechanism.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class PKCS5PBKD2Parameters implements Parameters {

  /**
   * The source of the salt value.
   */
  private long saltSource;

  /**
   * The data used as the input for the salt source.
   */
  private byte[] saltSourceData;

  /**
   * The number of iterations to perform when generating each block of random
   * data.
   */
  private long iterations;

  /**
   * The pseudo-random function (PRF) to used to generate the key.
   */
  private long pseudoRandomFunction;

  /**
   * The data used as the input for PRF in addition to the salt value.
   */
  private byte[] pseudoRandomFunctionData;

  /**
   * Create a new PBEDeriveParameters object with the given attributes.
   *
   * @param saltSource
   *          The source of the salt value. One of the constants defined in
   *          the SaltSourceType interface.
   * @param saltSourceData
   *          The data used as the input for the salt source.
   * @param iterations
   *          The number of iterations to perform when generating each block
   *          of random data.
   * @param pseudoRandomFunction
   *          The pseudo-random function (PRF) to used to generate the key.
   *          One of the constants defined in the PseudoRandomFunctionType
   *          interface.
   * @param pseudoRandomFunctionData
   *          The data used as the input for PRF in addition to the salt
   *          value.
   */
  public PKCS5PBKD2Parameters(long saltSource, byte[] saltSourceData,
      long iterations, long pseudoRandomFunction, byte[] pseudoRandomFunctionData) {
    if (saltSource != CKZ_SALT_SPECIFIED) {
      throw new IllegalArgumentException(
          "Illegal value for argument 'saltSource': " + Functions.ckzCodeToName(saltSource));
    }
    if (pseudoRandomFunction != CKP_PKCS5_PBKD2_HMAC_SHA1) {
      throw new IllegalArgumentException("Illegal value for argument 'pseudoRandomFunction': "
          + Functions.ckpCodeToName(pseudoRandomFunction));
    }
    this.saltSource = saltSource;
    this.saltSourceData = Functions.requireNonNull("saltSourceData", saltSourceData);
    this.iterations = iterations;
    this.pseudoRandomFunction = pseudoRandomFunction;
    this.pseudoRandomFunctionData = Functions.requireNonNull("pseudoRandomFunctionData", pseudoRandomFunctionData);
  }

  /**
   * Get this parameters object as an object of the CK_PKCS5_PBKD2_PARAMS
   * class.
   *
   * @return This object as a CK_PKCS5_PBKD2_PARAMS object.
   */
  @Override
  public CK_PKCS5_PBKD2_PARAMS getPKCS11ParamsObject() {
    CK_PKCS5_PBKD2_PARAMS params = new CK_PKCS5_PBKD2_PARAMS();

    params.saltSource = saltSource;
    params.pSaltSourceData = saltSourceData;
    params.iterations = iterations;
    params.prf = pseudoRandomFunction;
    params.pPrfData = pseudoRandomFunctionData;

    return params;
  }

  /**
   * Get the source of the salt value.
   *
   * @return The source of the salt value.
   */
  public long getSaltSource() {
    return saltSource;
  }

  /**
   * Get the data used as the input for the salt source.
   *
   * @return data used as the input for the salt source.
   */
  public byte[] getSaltSourceData() {
    return saltSourceData;
  }

  /**
   * Get the number of iterations to perform when generating each block of
   * random data.
   *
   * @return The number of iterations to perform when generating each block of
   *         random data.
   */
  public long getIterations() {
    return iterations;
  }

  /**
   * Get the pseudo-random function (PRF) to used to generate the key.
   *
   * @return The pseudo-random function (PRF) to used to generate the key.
   */
  public long getPseudoRandomFunction() {
    return pseudoRandomFunction;
  }

  /**
   * Get the data used as the input for PRF in addition to the salt value.
   *
   * @return The data used as the input for PRF in addition to the salt value.
   */
  public byte[] getPseudoRandomFunctionData() {
    return pseudoRandomFunctionData;
  }

  /**
   * Set the source of the salt value.
   *
   * @param saltSource
   *          The source of the salt value. One of the constants defined in
   *          the SaltSourceType interface
   */
  public void setSaltSource(long saltSource) {
    if (saltSource != CKZ_SALT_SPECIFIED) {
      throw new IllegalArgumentException("Illegal value for argument 'saltSource': "
          + Functions.ckzCodeToName(saltSource));
    }
    this.saltSource = saltSource;
  }

  /**
   * Set the data used as the input for the salt source.
   *
   * @param saltSourceData
   *          The data used as the input for the salt source.
   */
  public void setSaltSourceData(byte[] saltSourceData) {
    this.saltSourceData = Functions.requireNonNull("saltSourceData", saltSourceData);
  }

  /**
   * Set the number of iterations to perform when generating each block of
   * random data.
   *
   * @param iterations
   *          The number of iterations to perform when generating each block
   *          of random data.
   */
  public void setIterations(long iterations) {
    this.iterations = iterations;
  }

  /**
   * Set the pseudo-random function (PRF) to used to generate the key.
   *
   * @param pseudoRandomFunction
   *          The pseudo-random function (PRF) to used to generate the key.
   *          One of the constants defined in the PseudoRandomFunctionType
   *          interface.
   */
  public void setPseudoRandomFunction(long pseudoRandomFunction) {
    if (pseudoRandomFunction != CKP_PKCS5_PBKD2_HMAC_SHA1) {
      throw new IllegalArgumentException(
        "Illegal value for argument 'pseudoRandomFunction': " + Functions.ckpCodeToName(pseudoRandomFunction));
    }
    this.pseudoRandomFunction = pseudoRandomFunction;
  }

  /**
   * Set the data used as the input for PRF in addition to the salt value.
   *
   * @param pseudoRandomFunctionData
   *          The data used as the input for PRF in addition to the salt
   *          value.
   */
  public void setPseudoRandomFunctionData(byte[] pseudoRandomFunctionData) {
    this.pseudoRandomFunctionData = Functions.requireNonNull("pseudoRandomFunctionData", pseudoRandomFunctionData);
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "  Salt Source: " + Functions.ckzCodeToName(saltSource) +
        "\n  Salt Source Data (hex): " + Functions.toHex(saltSourceData) +
        "\n  Iterations (dec): " + iterations +
        "\n  Pseudo-Random Function: " + Functions.ckpCodeToName(pseudoRandomFunction) +
        "\n  Pseudo-Random Function Data (hex): " + Functions.toHex(pseudoRandomFunctionData);
  }

}
