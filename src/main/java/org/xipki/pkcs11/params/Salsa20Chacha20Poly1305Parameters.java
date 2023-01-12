package org.xipki.pkcs11.params;

import org.xipki.pkcs11.Functions;
import org.xipki.pkcs11.Util;

import java.lang.reflect.Constructor;

/**
 * This class encapsulates parameters for the Salsa20Chacha20 en/decryption.
 *
 * @author Lijun Liao (xipki)
 */
public class Salsa20Chacha20Poly1305Parameters implements Parameters {

  public static final String CLASS_CK_PARAMS = "sun.security.pkcs11.wrapper.CK_SALSA20_CHACHA20_POLY1305_PARAMS";

  private static final Constructor<?> constructor;

  private byte[] nonce;

  private byte[] aad;

  static {
    constructor = Util.getConstructor(CLASS_CK_PARAMS, byte[].class, byte[].class);
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
  public Salsa20Chacha20Poly1305Parameters(byte[] nonce, byte[] aad) {
    if (constructor == null) {
      throw new IllegalStateException(CLASS_CK_PARAMS + " is not available in the JDK");
    }

    this.nonce = Functions.requireNonNull("nonce", nonce);
    this.aad = aad;
  }

  /**
   * Get this parameters object as an object of the CK_SALSA20_CHACHA20_POLY1305_PARAMS class.
   *
   * @return This object as a CK_SALSA20_CHACHA20_POLY1305_PARAMS object.
   */
  @Override
  public Object getPKCS11ParamsObject() {
    try {
      return constructor.newInstance(nonce, aad);
    } catch (Exception ex) {
      throw new IllegalStateException("Could not create new instance of " + CLASS_CK_PARAMS, ex);
    }
  }

  /**
   * Returns the string representation of this object.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() +
        "\n  Nonce: " + Functions.toHex(nonce) + "\n  AAD: " + (aad == null ? " " : Functions.toHex(aad));
  }

}
