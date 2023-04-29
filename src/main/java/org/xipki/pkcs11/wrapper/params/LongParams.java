// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import sun.security.pkcs11.wrapper.CK_MECHANISM;

/**
 * This class encapsulates parameters CK_LONG.
 *
 * @author Lijun Liao (xipki)
 */
public class LongParams extends CkParams {

  /**
   * The PKCS#11 object.
   */
  protected final long params;

  /**
   * Create a new ObjectHandleParameters object using the given object.
   *
   * @param params
   *          The params.
   */
  public LongParams(long params) {
    this.params = params;
  }

  @Override
  public Long getParams() {
    return params;
  }

  @Override
  public CK_MECHANISM toCkMechanism(long mechanism) {
    return new CK_MECHANISM(mechanism, getParams());
  }

  @Override
  protected int getMaxFieldLen() {
    return 0;
  }

  @Override
  public String toString(String indent) {
    return indent + "Long Params: " + params;
  }

}
