// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Constants.Category;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_RSA_PKCS_OAEP_PARAMS;

/**
 * Represents the CK_RSA_PKCS_OAEP_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class RSA_PKCS_OAEP_PARAMS extends CkParams {

  private final CK_RSA_PKCS_OAEP_PARAMS params;

  /**
   * Create a new RSA_PKCS_OAEP_PARAMS object with the given attributes.
   *
   * @param hashAlg
   *          The message digest algorithm used to calculate the digest of the
   *          encoding parameter.
   * @param mgf
   *          The mask to apply to the encoded block. One of the constants
   *          defined in the MessageGenerationFunctionType interface.
   * @param source
   *          The source of the encoding parameter. One of the constants
   *          defined in the SourceType interface.
   * @param sourceData
   *          The data used as the input for the encoding parameter source.
   */
  public RSA_PKCS_OAEP_PARAMS(long hashAlg, long mgf, long source, byte[] sourceData) {
    params = new CK_RSA_PKCS_OAEP_PARAMS();
    params.hashAlg = hashAlg;
    params.mgf = mgf;
    params.source = source;
    params.pSourceData = sourceData;
  }

  @Override
  public CK_MECHANISM toCkMechanism(long mechanism) {
    throw new IllegalStateException("RSA OAEP unsupported in the underlying JDK");
  }

  @Override
  public CK_RSA_PKCS_OAEP_PARAMS getParams() {
    if (module == null) {
      return params;
    }

    long newHashAlg = module.genericToVendorCode(Category.CKM, params.hashAlg);
    long newMgf = module.genericToVendorCode(Category.CKG_MGF, params.mgf);
    if (newHashAlg == params.hashAlg && newMgf == params.mgf) {
      return params;
    }

    CK_RSA_PKCS_OAEP_PARAMS params0 = new CK_RSA_PKCS_OAEP_PARAMS();
    params0.hashAlg = newHashAlg;
    params0.mgf = newMgf;
    params0.source = params.source;
    params0.pSourceData = params.pSourceData;
    return params0;
  }

  @Override
  protected int getMaxFieldLen() {
    return 11; // pSourceData
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_RSA_PKCS_OAEP_PARAMS:" +
        val2Str(indent, "hashAlg", (module == null
            ? PKCS11Constants.ckmCodeToName(params.hashAlg)
            : module.codeToName(Category.CKM, params.hashAlg))) +
        val2Str(indent, "mgf", (module == null
            ? PKCS11Constants.codeToName(Category.CKG_MGF, params.mgf)
            : module.codeToName(Category.CKG_MGF, params.mgf))) +
        val2Str(indent, "source", PKCS11Constants.codeToName(Category.CKZ, params.source)) +
        ptr2str(indent, "pSourceData", params.pSourceData);
  }

}
