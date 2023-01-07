// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package demo.pkcs.pkcs11.wrapper.keygeneration;

import demo.pkcs.pkcs11.wrapper.TestBase;
import org.junit.Test;
import org.xipki.pkcs11.*;

import static org.xipki.pkcs11.PKCS11Constants.CKK_AES;
import static org.xipki.pkcs11.PKCS11Constants.CKM_AES_KEY_GEN;

/**
 * This demo program shows how to derive a DES3 key.
 */
public class DeriveKeyDemo extends TestBase {

  @Test
  public void main() throws Exception {
    Token token = getNonNullToken();
    Session session = openReadWriteSession(token);
    try {
      main0(token, session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Token token, Session session) throws PKCS11Exception {
    Mechanism keyGenerationMechanism = getSupportedMechanism(token, CKM_AES_KEY_GEN);

    AttributesTemplate baseKeyTemplate = newSecretKey(CKK_AES).valueLen(32).token(false).derive(true)
        .token(false) // we only have a read-only session, thus we only create a session object
        .sensitive(true).extractable(true);

    long baseKey = session.generateKey(keyGenerationMechanism, baseKeyTemplate);

    LOG.info("Base key " + baseKey);
    LOG.info("derive key");

    AttributesTemplate derivedKeyTemplate = newSecretKey(CKK_AES).valueLen(16)
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
