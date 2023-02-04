// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Functions;
import sun.security.pkcs11.wrapper.CK_MECHANISM;

/**
 * This class encapsulates parameters byte arrays.
 *
 * @author Lijun Liao (xipki)
 */
public class ByteArrayParams extends CkParams {

  private final byte[] bytes;

  public ByteArrayParams(byte[] bytes) {
    this.bytes = Functions.requireNonNull("bytes", bytes);
  }

  @Override
  public byte[] getParams() {
    return bytes;
  }

  @Override
  public CK_MECHANISM toCkMechanism(long mechanism) {
    return new CK_MECHANISM(mechanism, bytes);
  }

  @Override
  public String toString() {
    return "ByteArray Params: " + ptrToString("\n  ", bytes);
  }

}
