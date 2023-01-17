// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

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
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  cb: " + Functions.toHex(cb);
  }

  @Override
  public CK_AES_CTR_PARAMS getPKCS11ParamsObject() {
    return new CK_AES_CTR_PARAMS(cb);
  }

}
