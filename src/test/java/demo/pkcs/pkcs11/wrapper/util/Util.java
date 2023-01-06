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

package demo.pkcs.pkcs11.wrapper.util;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.pkcs11.*;
import org.xipki.util.Args;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This class contains only static methods. It is the place for all functions
 * that are used by several classes in this package.
 *
 * @author Karl Scheibelhofer
 * @author Lijun Liao
 */
public class Util {

  /**
   * Lists all available tokens of the given module and lets the user select
   * one, if there is more than one available.
   *
   * @param pkcs11Module
   *          The PKCS#11 module to use.
   * @return The selected token or null, if no token is available or the user
   *         canceled the action.
   * @exception PKCS11Exception
   *              If listing the tokens failed.
   */
  public static Token selectToken(PKCS11Module pkcs11Module) throws PKCS11Exception {
    return selectToken(pkcs11Module, null);
  }

  /**
   * Lists all available tokens of the given module and lets the user select
   * one, if there is more than one available. Supports token preselection.
   *
   * @param pkcs11Module
   *          The PKCS#11 module to use.
   * @param slotIndex
   *          The slot index, beginning with 0.
   * @return The selected token or null, if no token is available or the user
   *         canceled the action.
   * @exception PKCS11Exception
   *              If listing the tokens failed.
   */
  public static Token selectToken(PKCS11Module pkcs11Module, Integer slotIndex) throws PKCS11Exception {
    if (pkcs11Module == null) {
      throw new NullPointerException("Argument pkcs11Module must not be null.");
    }

    Slot[] slots = pkcs11Module.getSlotList(true);
    if (slots == null || slots.length == 0) {
      return null;
    } else if (slotIndex != null) {
      if (slotIndex >= slots.length) {
        return null;
      } else {
        Token token = slots[slotIndex].getToken();
        if (!token.getTokenInfo().hasFlagBit(CKF_TOKEN_INITIALIZED)) {
          throw new IllegalArgumentException("token is not initialized");
        } else {
          return token;
        }
      }
    } else {
      // return the first initialized token
      for (Slot slot : slots) {
        if (slot.getToken().getTokenInfo().hasFlagBit(CKF_TOKEN_INITIALIZED)) {
          return slot.getToken();
        }
      }

      throw new IllegalArgumentException("found no initialized token");
    }
  }

  /**
   * Opens an authorized session for the given token. If the token requires the
   * user to login for private operations, the method loggs in the user.
   *
   * @param token
   *          The token to open a session for.
   * @param rwSession
   *          If the session should be a read-write session. This may be
   *          Token.SessionReadWriteBehavior.RO_SESSION or
   *          Token.SessionReadWriteBehavior.RW_SESSION.
   * @param pin
   *          PIN.
   * @return The selected token or null, if no token is available or the user
   *         canceled the action.
   * @exception PKCS11Exception
   *              If listing the tokens failed.
   */
  public static Session openAuthorizedSession(Token token, boolean rwSession, char[] pin)
      throws PKCS11Exception {
    if (token == null) {
      throw new NullPointerException("Argument 'token' must not be null.");
    }

    Session session = token.openSession(rwSession);

    TokenInfo tokenInfo = token.getTokenInfo();
    if (tokenInfo.hasFlagBit(CKF_LOGIN_REQUIRED)) {
      if (tokenInfo.hasFlagBit(CKF_PROTECTED_AUTHENTICATION_PATH)) {
        System.out.print("Please enter the user-PIN at the PIN-pad of your reader.");
        System.out.flush();
        // the token prompts the PIN by other means; e.g. PIN-pad
        session.login(CKU_USER, null);
      } else {
        try {
          session.login(CKU_USER, pin);
        } catch (PKCS11Exception ex) {
          if (ex.getErrorCode() != CKR_USER_ALREADY_LOGGED_IN) {
            throw ex;
          }
        }
      }
    }

    return session;
  }

  public static String getCommontName(X500Principal name) {
    return getRdnValue(name, "CN");
  }

  public static String getRdnValue(X500Principal name, String rdnType) {
    String dn = name.getName();
    LdapName ldapDN;
    try {
      ldapDN = new LdapName(dn);
    } catch (InvalidNameException ex) {
      throw new IllegalArgumentException("invalid LdapName", ex);
    }
    for(Rdn rdn: ldapDN.getRdns()) {
      if (rdn.getType().equalsIgnoreCase(rdnType)) {
        Object obj = rdn.getValue();
        if (obj instanceof String) {
          return (String) obj;
        } else {
          return obj.toString();
        }
      }
    }

    return null;
  }

  public static byte[] encodedAsn1Integer(BigInteger bn) {
    byte[] encodedBn = bn.toByteArray();
    int len = encodedBn.length;

    byte[] encoded;
    int idx = 1;
    if (len > 0xFFFF) {
      encoded = new byte[5 + len];
      encoded[idx++] = (byte) 0x83;
      encoded[idx++] = (byte) (len >> 16);
      encoded[idx++] = (byte) (len >> 8);
      encoded[idx++] = (byte)  len;
    } else if(len > 0x7F) {
      encoded = new byte[4 + len];
      encoded[idx++] = (byte) 0x82;
      encoded[idx++] = (byte) (len >> 8);
      encoded[idx++] = (byte)  len;
    } else {
      encoded = new byte[2 + len];
      encoded[idx++] = (byte) len;
    }
    encoded[0] = 2; // tag
    System.arraycopy(encodedBn, 0, encoded, idx, encodedBn.length);
    return encoded;
  }

  public static boolean supports(Token token, long mechCode) throws PKCS11Exception {
    for (long mech : token.getMechanismList()) {
      if (mech == mechCode) {
        return true;
      }
    }
    return false;
  }

  public static byte[] dsaSigPlainToX962(byte[] signature) {
    Args.notNull(signature, "signature");
    if (signature.length % 2 != 0) {
      throw new IllegalArgumentException("signature.length must be even, but is odd");
    }
    byte[] ba = new byte[signature.length / 2];
    ASN1EncodableVector sigder = new ASN1EncodableVector();

    System.arraycopy(signature, 0, ba, 0, ba.length);
    sigder.add(new ASN1Integer(new BigInteger(1, ba)));

    System.arraycopy(signature, ba.length, ba, 0, ba.length);
    sigder.add(new ASN1Integer(new BigInteger(1, ba)));

    DERSequence seq = new DERSequence(sigder);
    try {
      return seq.getEncoded();
    } catch (IOException ex) {
      throw new IllegalArgumentException("IOException, message: " + ex.getMessage(), ex);
    }
  }

}
