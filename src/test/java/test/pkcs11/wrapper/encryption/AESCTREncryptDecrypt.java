// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encryption;

import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.Mechanism;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.Token;
import org.xipki.pkcs11.wrapper.params.AES_CTR_PARAMS;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via
 * CKM_AES_CTR.
 */
public class AESCTREncryptDecrypt extends SymmEncryptDecrypt {

  private final byte[] iv;

  public AESCTREncryptDecrypt() {
    iv = randomBytes(16);
  }

  @Override
  protected Mechanism getKeyGenMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, CKM_AES_KEY_GEN);
  }

  @Override
  protected Mechanism getEncryptionMech(Token token) throws PKCS11Exception {
    return getSupportedMechanism(token, CKM_AES_CTR, new AES_CTR_PARAMS(iv));
  }

  @Override
  protected AttributeVector getKeyTemplate() {
    return newSecretKey(CKK_AES).encrypt(true).decrypt(true).valueLen(16);
  }

}
