// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import sun.security.pkcs11.wrapper.CK_MECHANISM;

/**
 * This class encapsulates parameters CK_LONG.
 *
 * @author Lijun Liao (xipki)
 */
public class MechanismParams extends CkParams {

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
  public MechanismParams(long params) {
    this.params = params;
  }

  @Override
  public Long getParams() {
    assertModuleSet();
    return module.genericToVendor(PKCS11Constants.Category.CKM, params);
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
    return indent + "MechanismParams Params: " + (module == null ? PKCS11Constants.ckmCodeToName(params) :
        module.codeToName(PKCS11Constants.Category.CKM, params));
  }

}
