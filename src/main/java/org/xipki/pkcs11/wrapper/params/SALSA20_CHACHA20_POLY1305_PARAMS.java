// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.Util;
import sun.security.pkcs11.wrapper.CK_MECHANISM;

import java.lang.reflect.Constructor;

/**
 * This class encapsulates parameters for the Salsa20Chacha20 en/decryption.
 *
 * @author Lijun Liao (xipki)
 */
public class SALSA20_CHACHA20_POLY1305_PARAMS extends CkParams {

  private static final String CLASS_CK_PARAMS = "sun.security.pkcs11.wrapper.CK_SALSA20_CHACHA20_POLY1305_PARAMS";

  private static final Constructor<?> constructor;

  private static final Constructor<?> constructor_CK_MECHANISM;

  private final Object params;

  private final byte[] nonce;

  private final byte[] aad;

  static {
    constructor = Util.getConstructor(CLASS_CK_PARAMS, byte[].class, byte[].class);
    constructor_CK_MECHANISM = Util.getConstructorOfCK_MECHANISM(CLASS_CK_PARAMS);
  }

  /**
   * Create a new Salsa20Chacha20Poly1305Parameters object with the given attributes.
   *
   * @param nonce nonce (This should be never re-used with the same key.) <br>
   *               length of nonce in bits (is 64 for original, 96 for IETF (only for
   *               chacha20) and 192 for xchacha20/xsalsa20 variant)
   * @param aad additional authentication data. This data is authenticated but not encrypted.
   *
   */
  public SALSA20_CHACHA20_POLY1305_PARAMS(byte[] nonce, byte[] aad) {
    if (constructor == null) {
      throw new IllegalStateException(CLASS_CK_PARAMS + " is not available in the JDK");
    }

    this.nonce = Functions.requireNonNull("nonce", nonce);
    this.aad = aad;

    try {
      this.params = constructor.newInstance(nonce, aad);
    } catch (Exception ex) {
      throw new IllegalStateException("Could not create new instance of " + CLASS_CK_PARAMS, ex);
    }
  }

  /**
   * Get this parameters object as an object of the CK_SALSA20_CHACHA20_POLY1305_PARAMS class.
   *
   * @return This object as a CK_SALSA20_CHACHA20_POLY1305_PARAMS object.
   */
  @Override
  public Object getParams() {
    return params;
  }

  @Override
  public CK_MECHANISM toCkMechanism(long mechanism) {
    return buildCkMechanism(constructor_CK_MECHANISM, mechanism);
  }

  @Override
  protected int getMaxFieldLen() {
    return 6; // pNonce
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_SALSA20_CHACHA20_POLY1305_PARAMS:" +
        ptr2str(indent, "pNonce", nonce) +
        ptr2str(indent, "pAAD", aad);
  }

}
