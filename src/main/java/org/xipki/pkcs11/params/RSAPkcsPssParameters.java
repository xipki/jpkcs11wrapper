// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import org.xipki.pkcs11.Functions;
import org.xipki.pkcs11.Util;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;

/**
 * This class encapsulates parameters for the Mechanism.RSA_PKCS_PSS.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class RSAPkcsPssParameters extends RSAPkcsParameters {

  public static final String CLASS_CK_PARAMS = "sun.security.pkcs11.wrapper.CK_RSA_PKCS_PSS_PARAMS";

  private static final Constructor<?> constructor;

  private static final Constructor<?> constructorNoArgs;

  private static final Field hashAlgField;

  private static final Field mgfField;

  private static final Field sLenField;

  /**
   * The length of the salt value in octets.
   */
  private final int saltLength;

  static {
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
  }

  /**
   * Create a new RSAPkcsPssParameters object with the given attributes.
   *
   * @param hashAlgorithm
   *          The message digest algorithm used to calculate the digest of the encoding parameter.
   * @param maskGenerationFunction
   *          The mask to apply to the encoded block. One of the constants defined in the
   *          MessageGenerationFunctionType interface.
   * @param saltLength
   *          The length of the salt value in octets.
   *
   */
  public RSAPkcsPssParameters(long hashAlgorithm, long maskGenerationFunction, int saltLength) {
    super(hashAlgorithm, maskGenerationFunction);
    if (constructor == null && constructorNoArgs == null) {
      throw new IllegalStateException("could not find constructor for class " + CLASS_CK_PARAMS);
    }
    this.saltLength = saltLength;
  }

  /**
   * Get this parameters object as an object of the CK_RSA_PKCS_PSS_PARAMS class.
   *
   * @return This object as a CK_RSA_PKCS_PSS_PARAMS object.
   */
  @Override
  public Object getPKCS11ParamsObject() {
    if (constructorNoArgs != null) {
      try {
        Object ret = constructorNoArgs.newInstance();
        hashAlgField.set(ret, hashAlg);
        mgfField.set(ret, mgf);
        sLenField.set(ret, saltLength);
        return ret;
      } catch (Exception ex) {
        throw new IllegalStateException("Could not create new instance of " + CLASS_CK_PARAMS, ex);
      }
    } else {
      String hashAlgName = Functions.getHashAlgName(hashAlg);
      String mgfHashAlgName = Functions.getHashAlgName(mgf2HashAlgMap.get(mgf));
      try {
        return constructor.newInstance(hashAlgName, "MGF1", mgfHashAlgName, saltLength);
      } catch (Exception ex) {
        throw new IllegalStateException("Could not create new instance of " + CLASS_CK_PARAMS, ex);
      }
    }
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return super.toString() + "\n  Salt Length (octets, dec): " + saltLength;
  }

}
