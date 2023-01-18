// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import sun.security.pkcs11.wrapper.CK_ECDH1_DERIVE_PARAMS;
import org.xipki.pkcs11.Functions;
import sun.security.pkcs11.wrapper.CK_MECHANISM;

import static org.xipki.pkcs11.PKCS11Constants.*;

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
    Functions.requireAmong("kdf", kdf,
        CKD_NULL, CKD_SHA1_KDF, CKD_SHA1_KDF_ASN1, CKD_SHA1_KDF_CONCATENATE);
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
  public String toString() {
    return "CK_ECDH1_DERIVE_PARAMS:" +
        "\n  Key Derivation Function: " + codeToName(Category.CKD, params.kdf) +
        "\n  Public Data: " + ptrToString(params.pPublicData) +
        "\n  Shared Data: " + ptrToString(params.pSharedData);
  }

}
