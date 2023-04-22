// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import sun.security.pkcs11.wrapper.CK_AES_CTR_PARAMS;
import sun.security.pkcs11.wrapper.CK_MECHANISM;

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
public class AES_CTR_PARAMS extends CkParams {

  private final CK_AES_CTR_PARAMS params;

  private final byte[] cb;

  public AES_CTR_PARAMS(byte[] cb) {
    this.cb = requireNonNull("cb", cb);
    Functions.requireAmong("cb.length", cb.length, 16);
    this.params = new CK_AES_CTR_PARAMS(cb);
  }

  @Override
  public CK_AES_CTR_PARAMS getParams() {
    return params;
  }

  @Override
  public CK_MECHANISM toCkMechanism(long mechanism) {
    return new CK_MECHANISM(mechanism, getParams());
  }

  @Override
  protected int getMaxFieldLen() {
    return 2; // cb
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_AES_CTR_PARAMS:" +
        ptr2str(indent, "cb", cb);
  }

}
