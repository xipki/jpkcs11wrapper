/*
 *
 * Copyright (c) 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.pkcs11.parameters;

import org.xipki.pkcs11.Functions;
import org.xipki.pkcs11.Util;

import java.lang.reflect.Constructor;

/**
 * CK_CCM_PARAMS
 *
 * @author Lijun Liao
 */
public class GcmParameters implements Parameters {

  public static final String CLASS_CK_PARAMS = "sun.security.pkcs11.wrapper.CK_GCM_PARAMS";

  private static final Constructor<?> constructor;

  private final byte[] iv;
  private final byte[] aad;
  private final int tagBits;

  static {
    constructor = Util.getConstructor(CLASS_CK_PARAMS, int.class, byte[].class, byte[].class);
  }

  public GcmParameters(byte[] iv, byte[] aad, long tagBits) {
    if (constructor == null) {
      throw new IllegalStateException(CLASS_CK_PARAMS + " is not available in the JDK");
    }

    this.iv = iv;
    this.aad = aad;
    this.tagBits = (int) tagBits;
  }

  public Object getPKCS11ParamsObject() {
    try {
      return constructor.newInstance(tagBits, iv, aad);
    } catch (Exception ex) {
      throw new IllegalStateException("Could not create new instance of " + CLASS_CK_PARAMS, ex);
    }
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   *
   * @return A string representation of this object.
   */
  public String toString() {
    return "Class: " + getClass().getName() + "\n   IV: " + Functions.toHex(iv) +
        "\n  AAD: " + (aad == null ? " " : Functions.toHex(aad)) + "\n   TagBits: " + tagBits;
  }

}

