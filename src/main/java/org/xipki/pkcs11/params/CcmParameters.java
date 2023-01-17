// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import org.xipki.pkcs11.Functions;
import org.xipki.pkcs11.Util;

import java.lang.reflect.Constructor;

/**
 * CK_CCM_PARAMS
 *
 * @author Lijun Liao (xipki)
 */
public class CcmParameters implements Parameters {

  public static final String CLASS_CK_PARAMS = "sun.security.pkcs11.wrapper.CK_CCM_PARAMS";

  private static final Constructor<?> constructor;

  private int dataLen;
  private final byte[] nonce;
  private final byte[] aad;
  private final int macLen;

  static {
    constructor = Util.getConstructor(CLASS_CK_PARAMS, int.class, byte[].class, byte[].class, int.class);
  }

  public CcmParameters(int dataLen, byte[] nonce, byte[] aad, int macLen) {
    if (constructor == null) throw new IllegalStateException(CLASS_CK_PARAMS + " is not available in the JDK");

    this.nonce = Functions.requireNonNull("nonce", nonce);
    Functions.requireRange("nonce.length", nonce.length, 7, 13);
    this.macLen = Functions.requireAmong("macLen", macLen, 4, 6, 8, 10, 12, 14, 16);
    this.dataLen = dataLen;
    this.aad = aad;
  }

  public void setDataLen(int dataLen) {
    this.dataLen = dataLen;
  }

  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  ulDataLen: " + dataLen +
        "\n  nonce: " + Functions.toHex(nonce) +
        "\n  aad: " + (aad == null ? " " : Functions.toHex(aad)) + "\n  macLen: " + macLen;
  }

  @Override
  public Object getPKCS11ParamsObject() {
    try {
      return constructor.newInstance(macLen, nonce, aad, dataLen);
    } catch (Exception ex) {
      throw new IllegalStateException("Could not create new instance of " + CLASS_CK_PARAMS, ex);
    }
  }

}
