// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Constants.Category;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_RSA_PKCS_OAEP_PARAMS;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.ckmCodeToName;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.codeToName;

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
    params.source = Functions.requireAmong("source", source, 0, PKCS11Constants.CKZ_SALT_SPECIFIED);
    params.pSourceData = sourceData;
  }

  @Override
  public CK_MECHANISM toCkMechanism(long mechanism) {
    throw new IllegalStateException("RSA OAEP unsupported in the underlying JDK");
  }

  @Override
  public CK_RSA_PKCS_OAEP_PARAMS getParams() {
    assertModuleSet();
    CK_RSA_PKCS_OAEP_PARAMS params0 = new CK_RSA_PKCS_OAEP_PARAMS();
    params0.hashAlg = module.genericToVendor(Category.CKM, params.hashAlg);
    params0.mgf = module.genericToVendor(Category.CKG_MGF, params.mgf);
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
            ? ckmCodeToName(params.hashAlg) : module.codeToName(Category.CKM, params.hashAlg))) +
        val2Str(indent, "mgf", (module == null
            ? codeToName(Category.CKG_MGF, params.mgf) : module.codeToName(Category.CKG_MGF, params.mgf))) +
        val2Str(indent, "source", PKCS11Constants.codeToName(Category.CKZ, params.source)) +
        ptr2str(indent, "pSourceData", params.pSourceData);
  }

}
