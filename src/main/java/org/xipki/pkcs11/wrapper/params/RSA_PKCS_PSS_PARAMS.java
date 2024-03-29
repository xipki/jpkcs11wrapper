// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.Util;
import sun.security.pkcs11.wrapper.CK_MECHANISM;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Represents the CK_RSA_PKCS_PSS_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class RSA_PKCS_PSS_PARAMS extends CkParams {

  public static final String CLASS_CK_PARAMS = "sun.security.pkcs11.wrapper.CK_RSA_PKCS_PSS_PARAMS";

  private static final Constructor<?> constructor;

  private static final Constructor<?> constructorNoArgs;

  private static final Field hashAlgField;

  private static final Field mgfField;

  private static final Field sLenField;

  private static final Method CK_MECHANISM_method_setParameter;

  private static final Field CK_MECHANISM_field_pParameter;

  private static final Map<Long, Long> mgf2HashAlgMap;

  /**
   * The message digest algorithm used to calculate the digest of the encoding
   * parameter.
   */
  protected long hashAlg;

  /**
   * The mask to apply to the encoded block.
   */
  protected long mgf;

  /**
   * The length of the salt value in octets.
   */
  private final int sLen;

  private final Object params;

  static {
    Map<Long, Long> map = new HashMap<>();
    map.put(CKG_MGF1_SHA1,     CKM_SHA_1);
    map.put(CKG_MGF1_SHA224,   CKM_SHA224);
    map.put(CKG_MGF1_SHA256,   CKM_SHA256);
    map.put(CKG_MGF1_SHA384,   CKM_SHA384);
    map.put(CKG_MGF1_SHA512,   CKM_SHA512);
    map.put(CKG_MGF1_SHA3_224, CKM_SHA3_224);
    map.put(CKG_MGF1_SHA3_256, CKM_SHA3_256);
    map.put(CKG_MGF1_SHA3_384, CKM_SHA3_384);
    map.put(CKG_MGF1_SHA3_512, CKM_SHA3_512);
    mgf2HashAlgMap = Collections.unmodifiableMap(map);

    Class<?> clazz = Util.getClass(CLASS_CK_PARAMS);

    if (clazz != null) {
      constructor = Util.getConstructor(clazz, String.class, String.class, String.class, int.class);
      constructorNoArgs = (constructor != null) ? null : Util.getConstructor(clazz);

      hashAlgField = (constructorNoArgs == null) ? null : Util.getField(clazz, "hashAlg");
      mgfField = (constructorNoArgs == null) ? null : Util.getField(clazz, "mgf");
      sLenField = (constructorNoArgs == null) ? null : Util.getField(clazz, "sLen");
    } else {
      constructor = null;
      constructorNoArgs = null;
      hashAlgField = null;
      mgfField = null;
      sLenField = null;
    }

    // CK_MECHANISM
    clazz = CK_MECHANISM.class;
    CK_MECHANISM_field_pParameter = Util.getField(clazz, "pParameter");

    Class<?> paramClass = Util.getClass(RSA_PKCS_PSS_PARAMS.CLASS_CK_PARAMS);
    CK_MECHANISM_method_setParameter = paramClass == null ? null : Util.getMethod(clazz, "setParameter", paramClass);
  }

  /**
   * Create a new RSAPkcsPssParameters object with the given attributes.
   *
   * @param hashAlg
   *          The message digest algorithm used to calculate the digest of the encoding parameter.
   * @param mgf
   *          The mask to apply to the encoded block. One of the constants defined in the
   *          MessageGenerationFunctionType interface.
   * @param sLen
   *          The length of the salt value in octets.
   *
   */
  public RSA_PKCS_PSS_PARAMS(long hashAlg, long mgf, int sLen) {
    if (constructor == null && constructorNoArgs == null) {
      throw new IllegalStateException("could not find constructor for class " + CLASS_CK_PARAMS);
    }

    this.hashAlg = hashAlg;
    this.mgf = mgf;
    this.sLen = sLen;

    if (constructorNoArgs != null) {
      long realHashAlg = (module == null || (hashAlg & CKM_VENDOR_DEFINED) == 0)
          ? hashAlg : module.genericToVendorCode(Category.CKM, hashAlg);
      long realMgf     = (module == null || (mgf     & CKM_VENDOR_DEFINED) == 0)
          ? mgf : module.genericToVendorCode(Category.CKG_MGF, mgf);

      try {
        params = constructorNoArgs.newInstance();
        hashAlgField.set(params, realHashAlg);
        mgfField.set(params, realMgf);
        sLenField.set(params, sLen);
      } catch (Exception ex) {
        throw new IllegalStateException("Could not create new instance of " + CLASS_CK_PARAMS, ex);
      }
    } else {
      String hashAlgName = Functions.getHashAlgName(hashAlg);
      String mgfHashAlgName = Functions.getHashAlgName(mgf2HashAlgMap.get(mgf));
      try {
        params = constructor.newInstance(hashAlgName, "MGF1", mgfHashAlgName, sLen);
      } catch (Exception ex) {
        throw new IllegalStateException("Could not create new instance of " + CLASS_CK_PARAMS, ex);
      }
    }
  }

  @Override
  public Object getParams() {
    if (constructorNoArgs == null || module == null) {
      return params;
    }

    long newHashAlg = module.genericToVendorCode(Category.CKM, hashAlg);
    long newMgf = module.genericToVendorCode(Category.CKG_MGF, mgf);
    if (newHashAlg == hashAlg && newMgf == mgf) {
      return params;
    }

    try {
      Object ret = constructorNoArgs.newInstance();
      hashAlgField.set(ret, newHashAlg);
      mgfField.set(ret, newMgf);
      sLenField.set(ret, sLen);
      return ret;
    } catch (Exception ex) {
      throw new IllegalStateException("Could not create new instance of " + CLASS_CK_PARAMS, ex);
    }
  }

  @Override
  public CK_MECHANISM toCkMechanism(long mechanism) {
    CK_MECHANISM mech = new CK_MECHANISM(mechanism);
    Object params = getParams();
    try {
      if (CK_MECHANISM_field_pParameter != null) {
        CK_MECHANISM_field_pParameter.set(mech, params);
      } else if (CK_MECHANISM_method_setParameter != null) {
        CK_MECHANISM_method_setParameter.invoke(mech, params);
      } else {
        throw new IllegalStateException("could not construct CK_MECHANISM for RSA_PKCS_PSS_PARAMS");
      }
    } catch (IllegalAccessException | InvocationTargetException ex) {
      throw new IllegalStateException("could not construct CK_MECHANISM for RSA_PKCS_PSS_PARAMS", ex);
    }
    return mech;
  }

  @Override
  protected int getMaxFieldLen() {
    return 7; // hashAlg
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_RSA_PKCS_PSS_PARAMS:" +
        val2Str(indent, "hashAlg", codeToName(Category.CKM, hashAlg)) +
        val2Str(indent, "mgf", codeToName(Category.CKG_MGF, mgf)) +
        val2Str(indent, "sLen", sLen);
  }

}
