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

package demo.pkcs.pkcs11.wrapper.encryption;

import org.junit.Test;
import org.xipki.pkcs11.AttributeVector;
import org.xipki.pkcs11.Mechanism;
import org.xipki.pkcs11.PKCS11Exception;
import org.xipki.pkcs11.Token;
import org.xipki.pkcs11.parameters.GcmParameters;
import org.xipki.pkcs11.parameters.Salsa20Chacha20Poly1305Parameters;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via
 * CKM_CHACHA20_POLY1305.
 *
 * @author Lijun Liao
 */
public class AESChaCha20Poly1305EncryptDecrypt extends SymmEncryptDecrypt {

  private final byte[] iv;

  private final byte[] aad;

  public AESChaCha20Poly1305EncryptDecrypt() {
    iv = randomBytes(12);
    aad = new byte[20];
    // aad = "hello".getBytes();
  }

  @Test
  @Override
  public void main() throws PKCS11Exception {
    // check whether supported in current JDK
    try {
      new Salsa20Chacha20Poly1305Parameters(new byte[12], null);
    } catch (IllegalStateException ex) {
      System.err.println("AES-GCM unsupported in current JDK, skip");
      return;
    }

    super.main();
  }

  @Override
  protected Mechanism getKeyGenMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, CKM_CHACHA20_KEY_GEN);
  }

  @Override
  protected Mechanism getEncryptionMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, CKM_CHACHA20_POLY1305, new Salsa20Chacha20Poly1305Parameters(iv, aad));
  }

  @Override
  protected AttributeVector getKeyTemplate() {
    return newSecretKey(CKK_CHACHA20).encrypt(true).decrypt(true).valueLen(32);
  }

}
