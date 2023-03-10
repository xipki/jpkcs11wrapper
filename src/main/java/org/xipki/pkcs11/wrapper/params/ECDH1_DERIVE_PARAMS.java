// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.CK_ECDH1_DERIVE_PARAMS;
import sun.security.pkcs11.wrapper.CK_MECHANISM;

/**
 * Represents the CK_ECDH1_DERIVE_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class ECDH1_DERIVE_PARAMS extends CkParams {

  private final CK_ECDH1_DERIVE_PARAMS params;

  /**
   * Create a new ECDH1_DERIVE_PARAMS object with the given
   * attributes.
   *
   * @param kdf
   *          The key derivation function used on the shared secret value.
   *          One of the values defined in KeyDerivationFunctionType.
   * @param sharedData
   *          The data shared between the two parties.
   * @param publicData
   *          The other party's public key value.
   */
  public ECDH1_DERIVE_PARAMS(long kdf, byte[] sharedData, byte[] publicData) {
    requireNonNull("publicData", publicData);
    Functions.requireAmong("kdf", kdf, PKCS11Constants.CKD_NULL, PKCS11Constants.CKD_SHA1_KDF,
        PKCS11Constants.CKD_SHA1_KDF_ASN1, PKCS11Constants.CKD_SHA1_KDF_CONCATENATE);
    params = new CK_ECDH1_DERIVE_PARAMS(kdf, sharedData, publicData);
  }

  @Override
  public CK_ECDH1_DERIVE_PARAMS getParams() {
    return params;
  }

  @Override
  public CK_MECHANISM toCkMechanism(long mechanism) {
    return new CK_MECHANISM(mechanism, params);
  }

  @Override
  protected int getMaxFieldLen() {
    return 11; // pSharedData
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_ECDH1_DERIVE_PARAMS:" +
        val2Str(indent, "kdf", PKCS11Constants.codeToName(PKCS11Constants.Category.CKD, params.kdf)) +
        ptr2str(indent, "pPublicData", params.pPublicData) +
        ptr2str(indent, "pSharedData", params.pSharedData);
  }

}
