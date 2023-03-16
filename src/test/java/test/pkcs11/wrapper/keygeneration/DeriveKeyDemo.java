// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.keygeneration;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.Mechanism;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import test.pkcs11.wrapper.TestBase;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program shows how to derive a DES3 key.
 */
public class DeriveKeyDemo extends TestBase {

  @Test
  public void main() throws Exception {
    Mechanism keyGenerationMechanism = getSupportedMechanism(CKM_AES_KEY_GEN, CKF_GENERATE);

    AttributeVector baseKeyTemplate = newSecretKey(CKK_AES).valueLen(32).token(false).derive(true)
        .token(false) // we only have a read-only session, thus we only create a session object
        .sensitive(true).extractable(true);

    PKCS11Token token = getToken();
    long baseKey = token.generateKey(keyGenerationMechanism, baseKeyTemplate);

    LOG.info("Base key " + baseKey);
    LOG.info("derive key");

    AttributeVector derivedKeyTemplate = newSecretKey(CKK_AES).valueLen(16)
        .token(false).sensitive(true).extractable(true);

    /*
    byte[] iv = new byte[16];
    byte[] data = new byte[32];

    AesCbcEncryptDataParameters param = new AesCbcEncryptDataParameters(iv, data);
    Mechanism mechanism = getSupportedMechanism(token, CKM_AES_CBC_ENCRYPT_DATA);
    mechanism.setParameters(param);

    LOG.info("Derivation Mechanism: {}", mechanism);

    long derivedKey = session.deriveKey(mechanism, baseKey, derivedKeyTemplate);

    LOG.info("Derived key: {}", derivedKey);
     */
  }

}
