/*
 *
 * Copyright (c) 2022 - 2023 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.pkcs11.parameters;

import org.xipki.pkcs11.Functions;
import sun.security.pkcs11.wrapper.CK_AES_CTR_PARAMS;

/**
 * This class represents the necessary parameters required by
 * the CKM_AES_CTR mechanism as defined in CK_AES_CTR_PARAMS structure.
 *
 * <p><B>PKCS#11 structure:</B>
 * <PRE>
 * typedef struct CK_AES_CTR_PARAMS {
 *   CK_ULONG ulCounterBits;
 *   CK_BYTE cb[16];
 * } CK_AES_CTR_PARAMS;
 * </PRE>
 * @author Lijun Liao (xipki)
 */
public class AesCtrParameters implements Parameters {

  private final byte[] cb;

  public AesCtrParameters(byte[] cb) {
    this.cb = Functions.requireNonNull("cb", cb);
    Functions.requireAmong("cb.length", cb.length, 16);
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  public String toString() {
    return "Class: " + getClass().getName() + "\n  cb: " + Functions.toHex(cb);
  }

  public CK_AES_CTR_PARAMS getPKCS11ParamsObject() {
    return new CK_AES_CTR_PARAMS(cb);
  }

}
