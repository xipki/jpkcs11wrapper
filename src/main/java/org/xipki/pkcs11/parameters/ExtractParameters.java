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

/**
 * This class encapsulates parameters for Mechanisms.EXTRACT_KEY_FROM_KEY.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class ExtractParameters implements Parameters {

  /**
   * The bit of the base key that should be used as the first bit of the
   * derived key.
   */
  private long bitIndex;

  /**
   * Create a new ExtractParameters object with the given bit index.
   *
   * @param bitIndex
   *          The bit of the base key that should be used as the first bit of
   *          the derived key.
   */
  public ExtractParameters(long bitIndex) {
    this.bitIndex = bitIndex;
  }

  /**
   * Get this parameters object as a Long object.
   *
   * @return This object as a Long object.
   */
  @Override
  public Long getPKCS11ParamsObject() {
    return bitIndex;
  }

  /**
   * Get the bit of the base key that should be used as the first bit of the
   * derived key.
   *
   * @return The bit of the base key that should be used as the first bit of
   *         the derived key.
   */
  public long getBitIndex() {
    return bitIndex;
  }

  /**
   * Set the bit of the base key that should be used as the first bit of the
   * derived key.
   *
   * @param bitIndex
   *          The bit of the base key that should be used as the first bit of
   *          the derived key.
   */
  public void setBitIndex(long bitIndex) {
    this.bitIndex = bitIndex;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "  Bit Index (dec): " + bitIndex;
  }

}
