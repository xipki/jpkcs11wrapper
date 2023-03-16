// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encryption;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import org.xipki.pkcs11.wrapper.params.ByteArrayParams;
import test.pkcs11.wrapper.TestBase;

import java.util.Arrays;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This demo program uses a PKCS#11 module to wrap and unwrap a secret key.
 * The key to be wrapped must be extractable otherwise it can't be wrapped.
 */
public class WrapUnwrapEncrKey extends TestBase {

  @Test
  public void main() throws TokenException {
    LOG.info("##################################################");
    LOG.info("generate secret encryption/decryption key");
    Mechanism keyMechanism = getSupportedMechanism(CKM_AES_KEY_GEN, CKF_GENERATE);

    AttributeVector secretEncryptionKeyTemplate = newSecretKey(CKK_AES).token(false).valueLen(16)
        .encrypt(true).decrypt(true).private_(true).sensitive(true).extractable(true);

    PKCS11Token token = getToken();

    long encryptionKey = token.generateKey(keyMechanism, secretEncryptionKeyTemplate);

    byte[] rawData = randomBytes(1517);

    // be sure that your token can process the specified mechanism
    Mechanism wrapMechanism = getSupportedMechanism(CKM_AES_KEY_WRAP, CKF_WRAP);

    byte[] encryptIV = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    Mechanism encryptionMechanism = getSupportedMechanism(CKM_AES_CBC_PAD, CKF_ENCRYPT, new ByteArrayParams(encryptIV));

    // initialize for encryption
    byte[] buffer = new byte[rawData.length + 16];
    int outLen = token.encrypt(encryptionMechanism, encryptionKey, rawData, buffer);
    byte[] encryptedData = (outLen == buffer.length) ? buffer : Arrays.copyOf(buffer, outLen);

    LOG.info("##################################################");
    LOG.info("generate secret wrapping key");

    Mechanism wrapKeyMechanism = getSupportedMechanism(CKM_AES_KEY_GEN, CKF_GENERATE);
    AttributeVector wrapKeyTemplate = newSecretKey(CKK_AES).token(false).valueLen(16)
        .encrypt(true).decrypt(true).private_(true).sensitive(true).extractable(true).wrap(true).unwrap(true);

    long wrappingKey = token.generateKey(wrapKeyMechanism, wrapKeyTemplate);

    LOG.info("wrapping key");

    byte[] wrappedKey = token.wrapKey(wrapMechanism, wrappingKey, encryptionKey);
    AttributeVector keyTemplate = newSecretKey(CKK_AES).decrypt(true).token(false);

    LOG.info("unwrapping key");

    long unwrappedKey = token.unwrapKey(wrapMechanism, wrappingKey, wrappedKey, keyTemplate);

    LOG.info("##################################################");
    LOG.info("trying to decrypt");

    byte[] decryptIV = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    Mechanism decryptionMechanism = getSupportedMechanism(CKM_AES_CBC_PAD, CKF_DECRYPT, new ByteArrayParams(decryptIV));

    // initialize for decryption
    byte[] out = new byte[rawData.length + 16];
    outLen = token.decrypt(decryptionMechanism, unwrappedKey, encryptedData, out);
    byte[] decryptedData = Arrays.copyOf(out, outLen);

    Assert.assertArrayEquals(rawData, decryptedData);

    LOG.info("##################################################");
  }

}
