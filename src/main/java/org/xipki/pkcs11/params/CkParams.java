// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import org.xipki.pkcs11.Functions;
import sun.security.pkcs11.wrapper.CK_MECHANISM;

import java.lang.reflect.Constructor;

/**
 * Every Parameters-class implements this interface through which the module.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class CkParams {

  public abstract CK_MECHANISM toCkMechanism(long mechanism);

  /**
   * Get this parameters object as an object of the corresponding *_PARAMS
   * class of the sun.security.pkcs11.wrapper package.
   *
   * @return The object of the corresponding *_PARAMS class.
   */
  public abstract Object getParams();

  protected static String ptrToString(String prefix, byte[] data) {
    if (prefix == null) {
      prefix = "";
    }

    return data == null ? prefix + "<NULL_PTR>" : Functions.toString(prefix, data);
  }

  protected static <T> T requireNonNull(String paramName, T param) {
    return Functions.requireNonNull(paramName, param);
  }

  protected CK_MECHANISM buildCkMechanism(Constructor<?> constructor, long mechanismCode) {
    try {
      return (CK_MECHANISM) constructor.newInstance(mechanismCode, getParams());
    } catch (Exception ex) {
      throw new IllegalArgumentException("could not construct CK_MECHANISM", ex);
    }
  }

}
