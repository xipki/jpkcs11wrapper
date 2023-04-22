// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.xipki.pkcs11.wrapper.params.CkParams;
import org.xipki.pkcs11.wrapper.params.ECDH1_DERIVE_PARAMS;
import sun.security.pkcs11.wrapper.CK_MECHANISM;

/**
 * Objects of this class represent a mechanism as defined in PKCS#11. There are
 * constants defined for all mechanisms that PKCS#11 version 2.11 defines.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class Mechanism {

  private PKCS11Module module;

  /**
   * The code of the mechanism as defined in PKCS11Constants (or pkcs11t.h
   * likewise).
   */
  private final long mechanismCode;

  /**
   * The parameters of the mechanism. Not all mechanisms use these parameters.
   */
  private final CkParams parameters;

  /**
   * Constructor taking just the mechanism code as defined in PKCS11Constants.
   *
   * @param mechanismCode
   *          The mechanism code.
   */
  public Mechanism(long mechanismCode) {
    this(mechanismCode, null);
  }

  /**
   * Constructor taking just the mechanism code as defined in PKCS11Constants.
   *
   * @param mechanismCode The mechanism code.
   * @param parameters The mechanism parameters.
   */
  public Mechanism(long mechanismCode, CkParams parameters) {
    this.mechanismCode = mechanismCode;
    this.parameters = parameters;
  }

  public void setModule(PKCS11Module module) {
    this.module = module;
    if (parameters != null) {
      parameters.setModule(module);
    }
  }

  /**
   * Get the parameters object of this mechanism.
   *
   * @return The parameters of this mechanism. May be null.
   */
  public CkParams getParameters() {
    return parameters;
  }

  /**
   * Get the code of this mechanism as defined in PKCS11Constants (of
   * pkcs11t.h likewise).
   *
   * @return The code of this mechanism.
   */
  public long getMechanismCode() {
    return mechanismCode;
  }

  /**
   * Get the name of this mechanism.
   *
   * @return The name of this mechanism.
   */
  public String getName() {
    return module == null ? PKCS11Constants.ckmCodeToName(mechanismCode)
        : module.codeToName(PKCS11Constants.Category.CKM, mechanismCode);
  }

  public CK_MECHANISM toCkMechanism() {
    if (module == null) {
      throw new IllegalStateException("module is not set");
    }

    long realCode = module.genericToVendor(PKCS11Constants.Category.CKM, mechanismCode);
    if (parameters == null) {
      return new CK_MECHANISM(realCode);
    } else {
      return parameters.toCkMechanism(realCode);
    }
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return toString("");
  }

  public String toString(String indent) {
    return indent + "Mechanism: " + getName() + "\n" +
        indent + "Parameters:" + (parameters == null ? " null" : "\n" + parameters.toString(indent + "  "));
  }

}
