// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Util;
import sun.security.pkcs11.wrapper.CK_MECHANISM;

import java.lang.reflect.Constructor;

/**
 * Represents the CK_GCM_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class GCM_PARAMS extends CkParams {

  private static final String CLASS_CK_PARAMS = "sun.security.pkcs11.wrapper.CK_GCM_PARAMS";

  private static final Constructor<?> constructor;

  private static final Constructor<?> constructor_CK_MECHANISM;

  private final Object params;

  private final byte[] iv;
  private final byte[] aad;
  private final int tagBits;

  static {
    constructor = Util.getConstructor(CLASS_CK_PARAMS, int.class, byte[].class, byte[].class);
    constructor_CK_MECHANISM = Util.getConstructorOfCK_MECHANISM(CLASS_CK_PARAMS);
  }

  public GCM_PARAMS(byte[] iv, byte[] aad, int tagBits) {
    if (constructor == null) {
      throw new IllegalStateException(CLASS_CK_PARAMS + " is not available in the JDK");
    }

    this.iv = iv;
    this.aad = aad;
    this.tagBits = tagBits;

    try {
      this.params = constructor.newInstance(tagBits, iv, aad);
    } catch (Exception ex) {
      throw new IllegalStateException("Could not create new instance of " + CLASS_CK_PARAMS, ex);
    }
  }

  @Override
  public Object getParams() {
    return params;
  }

  @Override
  public CK_MECHANISM toCkMechanism(long mechanism) {
    return buildCkMechanism(constructor_CK_MECHANISM, mechanism);
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "CK_GCM_PARAMS:" +
        ptrToString("\n  pIv:       ", iv) +
        ptrToString("\n  pAAD:      ", aad) +
        "\n  ulTagBits: " + tagBits;
  }

}

