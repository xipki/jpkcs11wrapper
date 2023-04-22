// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.Util;
import sun.security.pkcs11.wrapper.CK_MECHANISM;

import java.lang.reflect.Constructor;

/**
 * Represents the CK_CCM_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class CCM_PARAMS extends CkParams {

  private static final String CLASS_CK_PARAMS = "sun.security.pkcs11.wrapper.CK_CCM_PARAMS";

  private static final Constructor<?> constructor_CK_MECHANISM;

  private static final Constructor<?> constructor;

  private final Object params;

  private int dataLen;
  private final byte[] nonce;
  private final byte[] aad;
  private final int macLen;

  static {
    constructor = Util.getConstructor(CLASS_CK_PARAMS, int.class, byte[].class, byte[].class, int.class);
    constructor_CK_MECHANISM = Util.getConstructorOfCK_MECHANISM(CLASS_CK_PARAMS);
  }

  public CCM_PARAMS(int dataLen, byte[] nonce, byte[] aad, int macLen) {
    if (constructor == null) {
      throw new IllegalStateException(CLASS_CK_PARAMS + " is not available in the JDK");
    }

    this.nonce = Functions.requireNonNull("nonce", nonce);
    Functions.requireRange("nonce.length", nonce.length, 7, 13);
    this.macLen = Functions.requireAmong("macLen", macLen, 4, 6, 8, 10, 12, 14, 16);
    this.dataLen = dataLen;
    this.aad = aad;

    try {
      params = constructor.newInstance(macLen, nonce, aad, dataLen);
    } catch (Exception ex) {
      throw new IllegalStateException("Could not create new instance of " + CLASS_CK_PARAMS, ex);
    }
  }

  public void setDataLen(int dataLen) {
    this.dataLen = dataLen;
  }

  @Override
  public CK_MECHANISM toCkMechanism(long mechanism) {
    return buildCkMechanism(constructor_CK_MECHANISM, mechanism, getParams());
  }

  @Override
  public Object getParams() {
    return params;
  }

  @Override
  protected int getMaxFieldLen() {
    return 9; // ulDataLen
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_CCM_PARAMS:" +
        val2Str(indent, "ulDataLen", dataLen) +
        ptr2str(indent, "pNonce", nonce) +
        ptr2str(indent, "pAAD", aad) +
        val2Str(indent, "ulMacLen", macLen);
  }

}
