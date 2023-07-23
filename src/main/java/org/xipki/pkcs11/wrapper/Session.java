// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.xipki.pkcs11.wrapper.attrs.*;
import org.xipki.pkcs11.wrapper.params.CkParamsWithExtra;
import org.xipki.pkcs11.wrapper.params.ExtraParams;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.PKCS11;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Session objects are used to perform cryptographic operations on a token. The application gets a
 * Session object by calling openSession on a certain Token object. Having the session object, the
 * application may log-in the user, if required.
 *
 * <pre>
 * <code>
 *   TokenInfo tokenInfo = token.getTokenInfo();
 *   // check, if log-in of the user is required at all
 *   if (tokenInfo.isLoginRequired()) {
 *     // check, if the token has own means to authenticate the user; e.g. a PIN-pad on the reader
 *     if (tokenInfo.isProtectedAuthenticationPath()) {
 *       System.out.println("Please enter the user PIN at the PIN-pad of your reader.");
 *       session.login(CKU_USER, null); // the token prompts the PIN by other means; e.g. PIN-pad
 *     } else {
 *       System.out.print("Enter user-PIN and press [return key]: ");
 *       System.out.flush();
 *       BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
 *       String userPINString = input.readLine();
 *       session.login(CKU_USER, userPINString.toCharArray());
 *     }
 *   }
 * </code>
 * </pre>
 *
 * If the application does not need the session any longer, it should close the
 * session.
 *
 * <pre>
 * <code>
 *   session.closeSession();
 * </code>
 * </pre>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class Session {

  private static final byte[] OID_curve25519 = Functions.encodeOid("1.3.101.110");

  private static final byte[] OID_curve448 = Functions.encodeOid("1.3.101.111");

  private static final byte[] OID_edwards25519 = Functions.encodeOid("1.3.101.112");

  private static final byte[] OID_edwards448 = Functions.encodeOid("1.3.101.113");

  private static final byte[] NAME_curve25519 = Functions.decodeHex("130a63757276653235353139");

  private static final byte[] NAME_curve448 = Functions.decodeHex("13086375727665343438");

  private static final byte[] NAME_edwards25519 = Functions.decodeHex("130c656477617264733235353139");

  private static final byte[] NAME_edwards448 = Functions.decodeHex("130a65647761726473343438");

  private static final int SIGN_TYPE_ECDSA = 1;

  private static final int SIGN_TYPE_SM2 = 2;

  private static final Method encrypt0;

  private static final Method encrypt1;

  private static final Method decrypt0;

  private static final Method decrypt1;

  /**
   * A reference to the underlying PKCS#11 module to perform the operations.
   */
  private final PKCS11Module module;

  /**
   * A reference to the underlying PKCS#11 module to perform the operations.
   */
  private final PKCS11 pkcs11;

  /**
   * The session handle to perform the operations with.
   */
  private long sessionHandle;

  /**
   * The token to perform the operations on.
   */
  private final Token token;

  private int signatureType;

  private long signOrVerifyKeyHandle;

  private ExtraParams signVerifyExtraParams;

  static {
    Class<?> clazz = PKCS11.class;
    decrypt0 = Util.getMethod(clazz, "C_Decrypt",
        long.class, byte[].class, int.class, int.class, byte[].class, int.class, int.class);

    encrypt0 = Util.getMethod(clazz, "C_Encrypt",
        long.class, byte[].class, int.class, int.class, byte[].class, int.class, int.class);

    decrypt1 = decrypt0 != null ? null : Util.getMethod(clazz, "C_Decrypt",
        long.class, long.class, byte[].class, int.class, int.class, long.class, byte[].class, int.class, int.class);

    encrypt1 = encrypt0 != null ? null : Util.getMethod(clazz, "C_Encrypt",
        long.class, long.class, byte[].class, int.class, int.class, long.class, byte[].class, int.class, int.class);
  }

  /**
   * Constructor taking the token and the session handle.
   *
   * @param token         The token this session operates with.
   * @param sessionHandle The session handle to perform the operations with.
   */
  protected Session(Token token, long sessionHandle) {
    this.token = Functions.requireNonNull("token", token);
    this.module = token.getSlot().getModule();
    this.pkcs11 = module.getPKCS11();
    this.sessionHandle = sessionHandle;
  }

  /**
   * Closes this session.
   *
   * @throws PKCS11Exception If closing the session failed.
   */
  public void closeSession() throws PKCS11Exception {
    final String method = "C_CloseSession";
    try {
      debugIn(method);
      pkcs11.C_CloseSession(sessionHandle);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Get the handle of this session.
   *
   * @return The handle of this session.
   */
  public long getSessionHandle() {
    return sessionHandle;
  }

  /**
   * Get information about this session.
   *
   * @return An object providing information about this session.
   * @throws PKCS11Exception If getting the information failed.
   */
  public SessionInfo getSessionInfo() throws PKCS11Exception {
    try {
      return new SessionInfo(pkcs11.C_GetSessionInfo(sessionHandle));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw module.convertException(ex);
    }
  }

  /**
   * Get the Module which this Session object operates with.
   *
   * @return The module of this session.
   */
  public PKCS11Module getModule() {
    return module;
  }

  /**
   * Get the token that created this Session object.
   *
   * @return The token of this session.
   */
  public Token getToken() {
    return token;
  }

  /**
   * Get the current operation state. This state can be used later to restore the operation to
   * exactly this state.
   *
   * @return The current operation state as a byte array.
   * @throws PKCS11Exception If saving the state fails or is not possible.
   */
  public byte[] getOperationState() throws PKCS11Exception {
    try {
      return pkcs11.C_GetOperationState(sessionHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw module.convertException(ex);
    }
  }

  /**
   * Sets the operation state of this session to a previously saved one. This method may need the
   * key used during the saved operation to continue, because it may not be possible to save a key
   * into the state's byte array. Refer to the PKCS#11 standard for details on this function.
   *
   * @param operationState          The previously saved state as returned by getOperationState().
   * @param encryptionKeyHandle     An encryption or decryption key handle, if an encryption or
   *                                decryption operation was saved  which should be continued, but
   *                                the keys could not be saved.
   * @param authenticationKeyHandle A signing, verification of MAC key handle, if a signing,
   *                                verification or MAC operation needs to be restored that could
   *                                not save the key.
   * @throws PKCS11Exception If restoring the state fails.
   * @see #getOperationState()
   */
  public void setOperationState(byte[] operationState, long encryptionKeyHandle, long authenticationKeyHandle)
      throws PKCS11Exception {
    try {
      pkcs11.C_SetOperationState(sessionHandle, operationState, encryptionKeyHandle, authenticationKeyHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw module.convertException(ex);
    }
  }

  public void setSessionHandle(long sessionHandle) {
    this.sessionHandle = sessionHandle;
  }

  /**
   * Logs in the user or the security officer to the session. Notice that all sessions of a token
   * have the same login state; i.e. if you login the user to one session all other open sessions of
   * this token get user rights.
   *
   * @param userType CKU_SO for the security officer or CKU_USER to login the user.
   * @param pin      The PIN. The security officer-PIN or the user-PIN depending on the userType parameter.
   * @throws PKCS11Exception If login fails.
   */
  public void login(long userType, char[] pin) throws PKCS11Exception {
    final String method = "C_Login";
    if (StaticLogger.isDebugEnabled()) {
      debugIn(method, "userType={}", codeToName(Category.CKU, userType));
    }
    try {
      pkcs11.C_Login(sessionHandle, userType, pin);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Logs out this session.
   *
   * @throws PKCS11Exception If logging out the session fails.
   */
  public void logout() throws PKCS11Exception {
    final String method = "C_Logout";
    debugIn(method);
    try {
      pkcs11.C_Logout(sessionHandle);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Create a new object on the token (or in the session). The application must provide a template
   * that holds enough information to create a certain object. For instance, if the application
   * wants to create a new DES key object it creates a new instance of the AttributesTemplate class to
   * serve as a template. The application must set all attributes of this new object which are
   * required for the creation of such an object on the token. Then it passes this DESSecretKey
   * object to this method to create the object on the token. Example: <code>
   * AttributesTemplate desKeyTemplate = new AttributesTemplate().newSecretKey(CKK_DES3);
   * // the key type is set by the DESSecretKey's constructor, so you need not do it
   * desKeyTemplate.value(myDesKeyValueAs8BytesLongByteArray)
   * .token(true)
   * .private(true);
   * .encrypt(true);
   * .decrypt(true);
   * ...
   * long theCreatedDESKeyObjectHandle = userSession.createObject(desKeyTemplate);
   * </code> Refer to the PKCS#11 standard to find out what attributes must be set for certain types
   * of objects to create them on the token.
   *
   * @param template The template object that holds all values that the new object on the token should
   *                 contain.
   * @return A new PKCS#11 Object that serves holds all the
   * (readable) attributes of the object on the token. In contrast to the templateObject,
   * this object might have certain attributes set to token-dependent default-values.
   * @throws PKCS11Exception If the creation of the new object fails. If it fails, the no new object was
   *                         created on the token.
   */
  public long createObject(AttributeVector template) throws PKCS11Exception {
    final String method = "C_CreateObject";
    if (StaticLogger.isDebugEnabled()) {
      long objClass = template.class_();
      if (objClass == CKO_PRIVATE_KEY || objClass == CKO_SECRET_KEY) {
        template.attributesAsSensitive(CKA_VALUE, // secret key, DSA, EC
            CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2, CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT); // RSA
      }
      debugIn(method, "template={}", template);
    }

    try {
      long hObject = pkcs11.C_CreateObject(sessionHandle, toOutCKAttributes(template));
      debugOut(method, "hObject={}", hObject);
      traceObject("created object", hObject);
      return hObject;
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  public long createPrivateKeyObject(AttributeVector template, PublicKey publicKey) throws PKCS11Exception {
    if (publicKey instanceof ECPublicKey && privateKeyWithEcPoint(template.keyType())) {
      byte[] ecParams = template.ecParams();
      Integer fieldSize = Functions.getECFieldSize(ecParams);
      ECPoint w = ((ECPublicKey) publicKey).getW();

      byte[] wx = Functions.asUnsignedByteArray(w.getAffineX());
      byte[] wy = Functions.asUnsignedByteArray(w.getAffineY());
      if (fieldSize == null) {
        fieldSize = Math.max(wx.length, wy.length);
      } else {
        if (wx.length > fieldSize || wy.length > fieldSize) {
          throw new IllegalStateException("should not happen, public key and ecParams do not match");
        }
      }

      byte[] ecPoint = new byte[1 + 2 * fieldSize];
      ecPoint[0] = 4;
      System.arraycopy(wx, 0, ecPoint, 1 + fieldSize - wx.length, wx.length);
      System.arraycopy(wy, 0, ecPoint, ecPoint.length - wy.length, wy.length);

      template.ecPoint(ecPoint);
    }
    return createObject(template);
  }

  public long createECPrivateKeyObject(AttributeVector template, byte[] ecPoint) throws PKCS11Exception {
    if (ecPoint != null && privateKeyWithEcPoint(template.keyType())) {
      template.ecPoint(ecPoint);
    }

    return createObject(template);
  }

  private boolean privateKeyWithEcPoint(Long keyType) {
    if (keyType == null) {
      return false;
    }

    if (CKK_EC == keyType) {
      return module.hasVendorBehaviour(PKCS11Module.BEHAVIOUR_EC_PRIVATEKEY_ECPOINT);
    } else if (CKK_VENDOR_SM2 == keyType) {
      return module.hasVendorBehaviour(PKCS11Module.BEHAVIOUR_SM2_PRIVATEKEY_ECPOINT);
    } else {
      return false;
    }
  }

  /**
   * Copy an existing object. The source object and a template object are given. Any value set in
   * the template object will override the corresponding value from the source object, when the new
   * object is created. See the PKCS#11 standard for details.
   *
   * @param sourceObjectHandle The source object of the copy operation.
   * @param template           A template object whose attribute values are used for the new object; i.e. they have
   *                           higher priority than the attribute values from the source object. May be null; in that
   *                           case the new object is just a one-to-one copy of the sourceObject.
   * @return The new object that is created by copying the source object and setting attributes to
   * the values given by the template.
   * @throws PKCS11Exception If copying the object fails for some reason.
   */
  public long copyObject(long sourceObjectHandle, AttributeVector template) throws PKCS11Exception {
    final String method = "C_CopyObject";

    debugIn(method, "sourceObjectHandle={}, template={}", sourceObjectHandle, template);
    try {
      long hObject = pkcs11.C_CopyObject(sessionHandle, sourceObjectHandle, toOutCKAttributes(template));
      debugOut(method, "hObject={}", hObject);
      traceObject("copied object", hObject);
      return hObject;
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Gets all present attributes of the given template object and writes them to the object to update
   * on the token (or in the session). Both parameters may refer to the same Java object. This is
   * possible, because this method only needs the object handle of the objectToUpdate, and gets the
   * attributes to set from the template. This means, an application can get the object using
   * createObject of findObject, then modify attributes of this Java object and then call this
   * method passing this object as both parameters. This will update the object on the token to the
   * values as modified in the Java object.
   *
   * @param objectToUpdateHandle The attributes of this object get updated.
   * @param template             Gets all present attributes of this template object and set this
   *                             attributes at the objectToUpdate.
   * @throws PKCS11Exception If updating the attributes fails. All or no attributes are updated.
   */
  public void setAttributeValues(long objectToUpdateHandle, AttributeVector template) throws PKCS11Exception {
    final String method = "C_SetAttributeValue";
    debugIn(method, "objectToUpdateHandle={}, template={}", objectToUpdateHandle, template);
    try {
      pkcs11.C_SetAttributeValue(sessionHandle, objectToUpdateHandle, toOutCKAttributes(template));
      debugOut(method);
      traceObject("object (after settingAttributeValues)", objectToUpdateHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Destroy a certain object on the token (or in the session). Give the object that you want to
   * destroy. This method uses only the internal object handle of the given object to identify the
   * object.
   *
   * @param objectHandle The object handle that should be destroyed.
   * @throws PKCS11Exception If the object could not be destroyed.
   */
  public void destroyObject(long objectHandle) throws PKCS11Exception {
    final String method = "C_DestroyObject";
    debugIn(method, "objectHandle={}", objectHandle);
    try {
      pkcs11.C_DestroyObject(sessionHandle, objectHandle);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Initializes a find operations that provides means to find objects by passing a template object.
   * This method get all set attributes of the template object and searches for all objects on the
   * token that match with these attributes.
   *
   * @param template The object that serves as a template for searching. If this object is null, the find
   *                 operation will find all objects that this session can see. Notice, that only a user
   *                 session will see private objects.
   * @throws PKCS11Exception If initializing the find operation fails.
   */
  public void findObjectsInit(AttributeVector template) throws PKCS11Exception {
    final String method = "C_FindObjectsInit";
    debugIn(method, "template={}", template);
    try {
      pkcs11.C_FindObjectsInit(sessionHandle, template == null ? null : toOutCKAttributes(template, true));
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Finds objects that match the template object passed to findObjectsInit. The application must
   * call findObjectsInit before calling this method. With maxObjectCount the application can
   * specify how many objects to return at once; i.e. the application can get all found objects by
   * subsequent calls to this method like maxObjectCount(1) until it receives an empty array (this
   * method never returns null!).
   *
   * @param maxObjectCount Specifies how many objects to return with this call.
   * @return An array of found objects. The maximum size of this array is maxObjectCount, the
   * minimum length is 0. Never returns null.
   * @throws PKCS11Exception A plain PKCS11Exception if something during PKCS11 FindObject went wrong, a
   *                         PKCS11Exception with a nested PKCS11Exception if the Exception is raised during
   *                         object parsing.
   */
  public long[] findObjects(int maxObjectCount) throws PKCS11Exception {
    final int countPerCall = 1000;
    if (maxObjectCount <= countPerCall) {
      return findObjects0(maxObjectCount);
    } else {
      List<Long> list = new LinkedList<>();
      for (int i = 0; i < maxObjectCount; i+= countPerCall) {
        int numObjects = Math.min(countPerCall, maxObjectCount - i);
        long[] handles = findObjects0(numObjects);
        for (long handle : handles) {
          list.add(handle);
        }

        if (handles.length < numObjects) {
          break;
        }
      }

      long[] ret = new long[list.size()];
      int idx = 0;
      for (Long handle : list) {
        ret[idx++] = handle;
      }
      return ret;
    }
  }

  private long[] findObjects0(int maxObjectCount) throws PKCS11Exception {
    final String method = "C_FindObjects";
    debugIn(method, "maxObjectCount={}", maxObjectCount);
    try {
      long[] hObjects = pkcs11.C_FindObjects(sessionHandle, maxObjectCount);
      if (StaticLogger.isDebugEnabled()) {
        debugOut(method, "hObjects={}", Arrays.toString(hObjects));
      }
      return hObjects;
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Finalizes a find operation. The application must call this method to finalize a find operation
   * before attempting to start any other operation.
   *
   * @throws PKCS11Exception If finalizing the current find operation was not possible.
   */
  public void findObjectsFinal() throws PKCS11Exception {
    final String method = "C_FindObjectsFinal";
    debugIn(method);
    try {
      pkcs11.C_FindObjectsFinal(sessionHandle);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  public long[] findAllObjectsSingle(AttributeVector template) throws PKCS11Exception {
    return findObjectsSingle(template, Integer.MAX_VALUE);
  }

  public long[] findObjectsSingle(AttributeVector template, int maxObjectCount) throws PKCS11Exception {
    findObjectsInit(template);
    try {
      return findObjects(maxObjectCount);
    } finally {
      findObjectsFinal();
    }
  }

  /**
   * Initializes a new encryption operation. The application must call this method before calling
   * any other encrypt* operation. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechanism to use for
   * encryption and the key for this operation. The key must have set its encryption flag. For the
   * mechanism the application may use a constant defined in the Mechanism class. Notice that the
   * key and the mechanism must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle The decryption key to use.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void encryptInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    final String method = "C_EncryptInit";
    mechanism.setModule(module);
    debugIn(method, "keyHandle={}, mechanism={}", keyHandle, mechanism);
    try {
      pkcs11.C_EncryptInit(sessionHandle, mechanism.toCkMechanism(), keyHandle);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Encrypts the given data with the key and mechanism given to the encryptInit method. This method
   * finalizes the current encryption operation; i.e. the application need (and should) not call
   * encryptFinal() after this call. For encrypting multiple pieces of data use encryptUpdate and
   * encryptFinal.
   *
   * @param in     the to-be-encrypted data
   * @param out    buffer for the encrypted data
   * @return the length of encrypted data
   * @throws PKCS11Exception If encrypting failed.
   */
  public int encrypt(byte[] in, byte[] out) throws PKCS11Exception {
    return encrypt(in, 0, in.length, out, 0, out.length);
  }

  public int encryptSingle(Mechanism mechanism, long keyHandle, byte[] in, byte[] out) throws PKCS11Exception {
    return encryptSingle(mechanism, keyHandle, in, 0, in.length, out, 0, out.length);
  }

  /**
   * Encrypts the given data with the key and mechanism given to the encryptInit method. This method
   * finalizes the current encryption operation; i.e. the application need (and should) not call
   * encryptFinal() after this call. For encrypting multiple pieces of data use encryptUpdate and
   * encryptFinal.
   *
   * @param in     buffer containing the to-be-encrypted data
   * @param inOfs  buffer offset of the to-be-encrypted data
   * @param inLen  length of the to-be-encrypted data
   * @param out    buffer for the encrypted data
   * @param outOfs buffer offset for the encrypted data
   * @param outLen buffer size for the encrypted data
   * @return the length of encrypted data
   * @throws PKCS11Exception If encrypting failed.
   */
  public int encrypt(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkParams(in, inOfs, inLen, out, outOfs, outLen);

    final String method = "C_Encrypt";
    int resLen;
    debugIn(method, "inOfs={}, inLen={}, outOfs={}, outLen", inOfs, inLen, outOfs, outLen);
    try {
      if (encrypt0 != null) {
        resLen = (int) encrypt0.invoke(pkcs11, sessionHandle, in, inOfs, inLen, out, outOfs, outLen);
      } else if (encrypt1 != null) {
        resLen = (int) encrypt1.invoke(pkcs11, sessionHandle, 0, in, inOfs, inLen, 0, out, outOfs, outLen);
      } else {
        throw new IllegalStateException("could not find C_ENCRYPT method");
      }
    } catch (IllegalAccessException ex) {
      throw new IllegalStateException(ex.getMessage(), ex);
    } catch (InvocationTargetException ex) {
      Throwable cause = ex.getCause();
      if (cause instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
        debugError(method, (sun.security.pkcs11.wrapper.PKCS11Exception) cause);
        throw module.convertException((sun.security.pkcs11.wrapper.PKCS11Exception) cause);
      } else {
        throw new IllegalStateException(ex.getMessage(), ex);
      }
    }

    return logOutLen(method, resLen);
  }

  public int encryptSingle(Mechanism mechanism, long keyHandle, byte[] in, int inOfs, int inLen,
                           byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    encryptInit(mechanism, keyHandle);
    return encrypt(in, inOfs, inLen, out, outOfs, outLen);
  }

  /**
   * This method can be used to encrypt multiple pieces of data; e.g. buffer-size pieces when
   * reading the data from a stream. Encrypts the given data with the key and mechanism given to the
   * encryptInit method. The application must call encryptFinal to get the final result of the
   * encryption after feeding in all data using this method.
   *
   * @param in     the to-be-encrypted data
   * @param out    buffer for the encrypted data
   * @return the length of encrypted data for this update
   * @throws PKCS11Exception If encrypting the data failed.
   */
  public int encryptUpdate(byte[] in, byte[] out) throws PKCS11Exception {
    return encryptUpdate(in, 0, in.length, out, 0, out.length);
  }

  /**
   * This method can be used to encrypt multiple pieces of data; e.g. buffer-size pieces when
   * reading the data from a stream. Encrypts the given data with the key and mechanism given to the
   * encryptInit method. The application must call encryptFinal to get the final result of the
   * encryption after feeding in all data using this method.
   *
   * @param in     buffer containing the to-be-encrypted data
   * @param inOfs  buffer offset of the to-be-encrypted data
   * @param inLen  length of the to-be-encrypted data
   * @param out    buffer for the encrypted data
   * @param outOfs buffer offset for the encrypted data
   * @param outLen buffer size for the encrypted data
   * @return the length of encrypted data for this update
   * @throws PKCS11Exception If encrypting the data failed.
   */
  public int encryptUpdate(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    final String method = "C_EncryptUpdate";
    checkParams(in, inOfs, inLen, out, outOfs, outLen);
    debugIn(method, "inOfs={}, inLen={}, outOfs={}, outLen", inOfs, inLen, outOfs, outLen);
    try {
      return logOutLen(method,
          pkcs11.C_EncryptUpdate(sessionHandle, 0, in, inOfs, inLen, 0, out, outOfs, outLen));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * This method finalizes an encrypt operation and returns the final result. Use this method, if
   * you fed in the data using encryptUpdate. If you used the encrypt(byte[]) method, you need not
   * (and shall not) call this method, because encrypt(byte[]) finalizes the encryption itself.
   *
   * @param out    buffer for the encrypted data
   * @param outOfs buffer offset for the encrypted data
   * @param outLen buffer size for the encrypted data
   * @return the length of the last part of the encrypted data
   * @throws PKCS11Exception If calculating the final result failed.
   */
  public int encryptFinal(byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    final String method = "C_EncryptFinal";
    checkOutParams(out, outOfs, outLen);
    debugIn(method, "outOfs={}, outLen", outOfs, outLen);
    try {
      return logOutLen(method, pkcs11.C_EncryptFinal(sessionHandle, 0, out, outOfs, outLen));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Initializes a new decryption operation. The application must call this method before calling
   * any other decrypt* operation. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechanism to use for
   * decryption and the key for this operation. The key must have set its decryption flag. For the
   * mechanism the application may use a constant defined in the Mechanism class. Notice that the
   * key and the mechanism must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle The decryption key to use.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void decryptInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    final String method = "C_DecryptInit";
    mechanism.setModule(module);
    debugIn(method, "keyHandle={}, mechanism={}", keyHandle, mechanism);
    try {
      pkcs11.C_DecryptInit(sessionHandle, mechanism.toCkMechanism(), keyHandle);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Decrypts the given data with the key and mechanism given to the decryptInit method. This method
   * finalizes the current decryption operation; i.e. the application need (and should) not call
   * decryptFinal() after this call. For decrypting multiple pieces of data use decryptUpdate and
   * decryptFinal.
   *
   * @param in     the to-be-decrypted data
   * @param out    buffer for the decrypted data
   * @return the length of decrypted data
   * @throws PKCS11Exception If decrypting failed.
   */
  public int decrypt(byte[] in, byte[] out) throws PKCS11Exception {
    return decrypt(in, 0, in.length, out, 0, out.length);
  }

  public int decryptSingle(Mechanism mechanism, long keyHandle, byte[] in, byte[] out) throws PKCS11Exception {
    return decryptSingle(mechanism, keyHandle, in, 0, in.length, out, 0, out.length);
  }

  /**
   * Decrypts the given data with the key and mechanism given to the decryptInit method. This method
   * finalizes the current decryption operation; i.e. the application need (and should) not call
   * decryptFinal() after this call. For decrypting multiple pieces of data use decryptUpdate and
   * decryptFinal.
   *
   * @param in     buffer containing the to-be-decrypted data
   * @param inOfs  buffer offset of the to-be-decrypted data
   * @param inLen  length of the to-be-decrypted data
   * @param out    buffer for the decrypted data
   * @param outOfs buffer offset for the decrypted data
   * @param outLen buffer size for the decrypted data
   * @return the length of decrypted data
   * @throws PKCS11Exception If decrypting failed.
   */
  public int decrypt(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkParams(in, inOfs, inLen, out, outOfs, outLen);

    final String method = "C_Decrypt";
    debugIn(method, "inOfs={}, inLen={}, outOfs={}, outLen", inOfs, inLen, outOfs, outLen);

    int resLen;
    try {
      if (decrypt0 != null) {
        resLen = (int) decrypt0.invoke(pkcs11, sessionHandle, in, inOfs, inLen, out, outOfs, outLen);
      } else if (decrypt1 != null) {
        resLen = (int) decrypt1.invoke(pkcs11, sessionHandle, 0, in, inOfs, inLen, 0, out, outOfs, outLen);
      } else {
        throw new IllegalStateException("could not find C_DECRYPT method");
      }
    } catch (IllegalAccessException ex) {
      throw new IllegalStateException(ex.getMessage(), ex);
    } catch (InvocationTargetException ex) {
      Throwable cause = ex.getCause();
      if (cause instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
        debugError(method, (sun.security.pkcs11.wrapper.PKCS11Exception) cause);
        throw module.convertException((sun.security.pkcs11.wrapper.PKCS11Exception) cause);
      } else {
        throw new IllegalStateException(ex.getMessage(), ex);
      }
    }

    return logOutLen(method, resLen);
  }

  public int decryptSingle(Mechanism mechanism, long keyHandle, byte[] in, int inOfs, int inLen,
                           byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    decryptInit(mechanism, keyHandle);
    return decrypt(in, inOfs, inLen, out, outOfs, outLen);
  }

  /**
   * This method can be used to decrypt multiple pieces of data; e.g. buffer-size pieces when
   * reading the data from a stream. Decrypts the given data with the key and mechanism given to the
   * decryptInit method. The application must call decryptFinal to get the final result of the
   * encryption after feeding in all data using this method.
   *
   * @param in     the to-be-decrypted data
   * @param out    buffer for the decrypted data
   * @return the length of decrypted data for this update
   * @throws PKCS11Exception If decrypting the data failed.
   */
  public int decryptUpdate(byte[] in, byte[] out) throws PKCS11Exception {
    return decryptUpdate(in, 0, in.length, out, 0, out.length);
  }

  /**
   * This method can be used to decrypt multiple pieces of data; e.g. buffer-size pieces when
   * reading the data from a stream. Decrypts the given data with the key and mechanism given to the
   * decryptInit method. The application must call decryptFinal to get the final result of the
   * encryption after feeding in all data using this method.
   *
   * @param in     buffer containing the to-be-decrypted data
   * @param inOfs  buffer offset of the to-be-decrypted data
   * @param inLen  length of the to-be-decrypted data
   * @param out    buffer for the decrypted data
   * @param outOfs buffer offset for the decrypted data
   * @param outLen buffer size for the decrypted data
   * @return the length of decrypted data for this update
   * @throws PKCS11Exception If decrypting the data failed.
   */
  public int decryptUpdate(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    final String method = "C_DecryptUpdate";
    checkParams(in, inOfs, inLen, out, outOfs, outLen);
    debugIn(method, "inOfs={}, inLen={}, outOfs={}, outLen", inOfs, inLen, outOfs, outLen);
    try {
      return logOutLen(method,
          pkcs11.C_DecryptUpdate(sessionHandle, 0, in, inOfs, inLen, 0, out, outOfs, outLen));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * This method finalizes a decryption operation and returns the final result. Use this method, if
   * you fed in the data using decryptUpdate. If you used the decrypt(byte[]) method, you need not
   * (and shall not) call this method, because decrypt(byte[]) finalizes the decryption itself.
   *
   * @param out    buffer for the decrypted data
   * @param outOfs buffer offset for the decrypted data
   * @param outLen buffer size for the decrypted data
   * @return the length of this last part of decrypted data
   * @throws PKCS11Exception If calculating the final result failed.
   */
  public int decryptFinal(byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    final String method = "C_DecryptFinal";
    checkOutParams(out, outOfs, outLen);
    debugIn(method, "outOfs={}, outLen", outOfs, outLen);
    try {
      return logOutLen(method, pkcs11.C_DecryptFinal(sessionHandle, 0, out, outOfs, outLen));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Initializes a new digesting operation. The application must call this method before calling any
   * other digest* operation. Before initializing a new operation, any currently pending operation
   * must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechanism to use for
   * digesting for this operation. For the mechanism the application may use a constant defined in
   * the Mechanism class.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.SHA_1.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void digestInit(Mechanism mechanism) throws PKCS11Exception {
    final String method = "C_DigestInit";
    mechanism.setModule(module);
    debugIn(method, "mechanism={}", mechanism);
    try {
      pkcs11.C_DigestInit(sessionHandle, mechanism.toCkMechanism());
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Digests the given data with the mechanism given to the digestInit method.
   * This method finalizes the current digesting operation; i.e. the
   * application need (and should) not call digestFinal() after this call. For
   * digesting multiple pieces of data use digestUpdate and digestFinal.
   *
   * @param in     the to-be-digested data
   * @param out    buffer for the digested data
   * @return the length of digested data for this update
   * @throws PKCS11Exception If digesting the data failed.
   */
  public int digestFinal(byte[] in, byte[] out) throws PKCS11Exception {
    return digestFinal(in, 0, in.length, out, 0, out.length);
  }

  /**
   * Digests the given data with the mechanism given to the digestInit method.
   * This method finalizes the current digesting operation; i.e. the
   * application need (and should) not call digestFinal() after this call. For
   * digesting multiple pieces of data use digestUpdate and digestFinal.
   *
   * @param in     buffer containing the to-be-digested data
   * @param inOfs  buffer offset of the to-be-digested data
   * @param inLen  length of the to-be-digested data
   * @param out    buffer for the digested data
   * @param outOfs buffer offset for the digested data
   * @param outLen buffer size for the digested data
   * @return the length of digested data for this update
   * @throws PKCS11Exception If digesting the data failed.
   */
  public int digestFinal(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkParams(in, inOfs, inLen, out, outOfs, outLen);

    digestUpdate(in, inOfs, inLen);
    return digestFinal(out, outOfs, outLen);
  }

  /**
   * Digests the given data with the mechanism given to the digestInit method. This method finalizes
   * the current digesting operation; i.e. the application need (and should) not call digestFinal()
   * after this call. For digesting multiple pieces of data use digestUpdate and digestFinal.
   *
   * @param in     the to-be-digested data
   * @param out    buffer for the digested data
   * @return the length of digested data for this update
   * @throws PKCS11Exception If digesting the data failed.
   */
  public int digest(byte[] in, byte[] out) throws PKCS11Exception {
    return digest(in, 0, in.length, out, 0, out.length);
  }

  public int digestSingle(Mechanism mechanism, byte[] in, byte[] out) throws PKCS11Exception {
    return digestSingle(mechanism, in, 0, in.length, out, 0, out.length);
  }

  /**
   * Digests the given data with the mechanism given to the digestInit method. This method finalizes
   * the current digesting operation; i.e. the application need (and should) not call digestFinal()
   * after this call. For digesting multiple pieces of data use digestUpdate and digestFinal.
   *
   * @param in     buffer containing the to-be-digested data
   * @param inOfs  buffer offset of the to-be-digested data
   * @param inLen  length of the to-be-digested data
   * @param out    buffer for the digested data
   * @param outOfs buffer offset for the digested data
   * @param outLen buffer size for the digested data
   * @return the length of digested data for this update
   * @throws PKCS11Exception If digesting the data failed.
   */
  public int digest(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen)
      throws PKCS11Exception {
    return digestFinal(in, inOfs, inLen, out, outOfs, outLen);
  }

  public int digestSingle(Mechanism mechanism, byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen)
      throws PKCS11Exception {
    final String method = "C_DigestSingle";
    checkParams(in, inOfs, inLen, out, outOfs, outLen);
    mechanism.setModule(module);
    debugIn(method, "mechanism={}, inOfs={}, inLen={}, outOfs={}, outLen",
        mechanism, inOfs, inLen, outOfs, outLen);

    try {
      return logOutLen(method,
          pkcs11.C_DigestSingle(sessionHandle, mechanism.toCkMechanism(), in, inOfs, inLen, out, outOfs, outLen));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * This method can be used to digest multiple pieces of data; e.g. buffer-size pieces when reading
   * the data from a stream. Digests the given data with the mechanism given to the digestInit
   * method. The application must call digestFinal to get the final result of the digesting after
   * feeding in all data using this method.
   *
   * @param in the to-be-digested data
   * @throws PKCS11Exception If digesting the data failed.
   */
  public void digestUpdate(byte[] in) throws PKCS11Exception {
    digestUpdate(in, 0, in.length);
  }

  /**
   * This method can be used to digest multiple pieces of data; e.g. buffer-size pieces when reading
   * the data from a stream. Digests the given data with the mechanism given to the digestInit
   * method. The application must call digestFinal to get the final result of the digesting after
   * feeding in all data using this method.
   *
   * @param in    buffer containing the to-be-digested data
   * @param inOfs buffer offset of the to-be-digested data
   * @param inLen length of the to-be-digested data
   * @throws PKCS11Exception If digesting the data failed.
   */
  public void digestUpdate(byte[] in, int inOfs, int inLen) throws PKCS11Exception {
    final String method = "C_DigestUpdate";
    checkInParams(in, inOfs, inLen);
    debugIn(method, "inOfs={}, inLen={}", inOfs, inLen);

    try {
      pkcs11.C_DigestUpdate(sessionHandle, 0, in, inOfs, inLen);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * This method is similar to digestUpdate and can be combined with it during one digesting
   * operation. This method digests the value of the given secret key.
   *
   * @param keyHandle The key to digest the value of.
   * @throws PKCS11Exception If digesting the key failed.
   */
  public void digestKey(long keyHandle) throws PKCS11Exception {
    final String method = "C_DigestUpdate";
    debugIn(method, "keyHandle={}", keyHandle);
    try {
      pkcs11.C_DigestKey(sessionHandle, keyHandle);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * This method finalizes a digesting operation and returns the final result. Use this method, if
   * you fed in the data using digestUpdate and/or digestKey. If you used the digest(byte[]) method,
   * you need not (and shall not) call this method, because digest(byte[]) finalizes the digesting
   * itself.
   *
   * @param out    buffer for the message digest
   * @param outOfs buffer offset for the message digest
   * @param outLen buffer size for the message digest
   * @return the length of message digest
   * @throws PKCS11Exception If calculating the final message digest failed.
   */
  public int digestFinal(byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    final String method = "C_DigestFinal";
    checkOutParams(out, outOfs, outLen);
    debugIn(method, "outOfs={}, outLen", outOfs, outLen);
    try {
      return logOutLen(method, pkcs11.C_DigestFinal(sessionHandle, out, outOfs, outLen));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  private void initSignVerify(Mechanism mechanism, long keyHandle) {
    this.signOrVerifyKeyHandle = keyHandle;
    long code = mechanism.getMechanismCode();
    if (code == CKM_ECDSA             || code == CKM_ECDSA_SHA1
        || code == CKM_ECDSA_SHA224   || code == CKM_ECDSA_SHA256
        || code == CKM_ECDSA_SHA384   || code == CKM_ECDSA_SHA512
        || code == CKM_ECDSA_SHA3_224 || code == CKM_ECDSA_SHA3_256
        || code == CKM_ECDSA_SHA3_384 || code == CKM_ECDSA_SHA3_512) {
      signatureType = SIGN_TYPE_ECDSA;
    } else if (code == CKM_VENDOR_SM2 || code == CKM_VENDOR_SM2_SM3) {
      signatureType = SIGN_TYPE_SM2;
    } else {
      signatureType = 0;
    }

    if (mechanism.getParameters() instanceof CkParamsWithExtra) {
      signVerifyExtraParams = ((CkParamsWithExtra) mechanism.getParameters()).getExtraParams();
    } else {
      signVerifyExtraParams = null;
    }
  }

  /**
   * Initializes a new signing operation. Use it for signatures and MACs. The application must call
   * this method before calling any other sign* operation. Before initializing a new operation, any
   * currently pending operation must be finalized using the appropriate *Final method (e.g.
   * digestFinal()). There are exceptions for dual-function operations. This method requires the
   * mechanism to use for signing and the key for this operation. The key must have set its sign
   * flag. For the mechanism the application may use a constant defined in the Mechanism class.
   * Notice that the key and the mechanism must be compatible; i.e. you cannot use a DES key with
   * the RSA mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param keyHandle The signing key to use.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void signInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    final String method = "C_SignInit";
    mechanism.setModule(module);
    try {
      initSignVerify(mechanism, keyHandle);
      debugIn(method, "keyHandle={}, mechanism={}", keyHandle, mechanism);
      pkcs11.C_SignInit(sessionHandle, mechanism.toCkMechanism(), keyHandle);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Signs the given data with the key and mechanism given to the signInit method. This method
   * finalizes the current signing operation; i.e. the application need (and should) not call
   * signFinal() after this call. For signing multiple pieces of data use signUpdate and signFinal.
   *
   * @param data The data to sign.
   * @return The signed data.
   * @throws PKCS11Exception If signing the data failed.
   */
  public byte[] sign(byte[] data) throws PKCS11Exception {
    Functions.requireNonNull("data", data);
    final String method = "C_Sign";
    debugIn(method, "data.length={}", len(data));
    try {
      byte[] sigValue = pkcs11.C_Sign(sessionHandle, data);
      debugOut("C_Sign", "rv.length={}", len(sigValue));
      return fixSignOutput(sigValue);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  public byte[] signSingle(Mechanism mechanism, long keyHandle, byte[] data) throws PKCS11Exception {
    signInit(mechanism, keyHandle);
    return sign(data);
  }

  /**
   * This method can be used to sign multiple pieces of data; e.g. buffer-size pieces when reading
   * the data from a stream. Signs the given data with the mechanism given to the signInit method.
   * The application must call signFinal to get the final result of the signing after feeding in all
   * data using this method.
   *
   * @param in buffer containing the to-be-signed data
   * @throws PKCS11Exception If signing the data failed.
   */
  public void signUpdate(byte[] in) throws PKCS11Exception {
    signUpdate(in, 0, in.length);
  }

  /**
   * This method can be used to sign multiple pieces of data; e.g. buffer-size pieces when reading
   * the data from a stream. Signs the given data with the mechanism given to the signInit method.
   * The application must call signFinal to get the final result of the signing after feeding in all
   * data using this method.
   *
   * @param in    buffer containing the to-be-signed data
   * @param inOfs buffer offset of the to-be-signed data
   * @param inLen length of the to-be-signed data
   * @throws PKCS11Exception If signing the data failed.
   */
  public void signUpdate(byte[] in, int inOfs, int inLen) throws PKCS11Exception {
    final String method = "C_SignUpdate";
    checkInParams(in, inOfs, inLen);
    debugIn(method, "inOfs={}, inLen={}", inOfs, inLen);

    try {
      pkcs11.C_SignUpdate(sessionHandle, 0, in, inOfs, inLen);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * This method finalizes a signing operation and returns the final result. Use this method, if you
   * fed in the data using signUpdate. If you used the sign(byte[]) method, you need not (and shall
   * not) call this method, because sign(byte[]) finalizes the signing operation itself.
   *
   * @return The final result of the signing operation; i.e. the signature
   * value.
   * @throws PKCS11Exception If calculating the final signature value failed.
   */
  public byte[] signFinal() throws PKCS11Exception {
    final String method = "C_SignFinal";
    debugIn(method);
    try {
      byte[] sigValue = pkcs11.C_SignFinal(sessionHandle, 0);
      debugOut(method, "rv.length={}", len(sigValue));
      return fixSignOutput(sigValue);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  private byte[] fixSignOutput(byte[] signatureValue) {
    if (signatureType == 0) {
      return signatureValue;
    }

    synchronized (module) {
      if (signatureType == SIGN_TYPE_ECDSA) {
        Boolean b = module.getEcdsaSignatureFixNeeded();
        if (b == null) {
          StaticLogger.info("EcdsaSignatureFixNeeded: null");
        } else {
          StaticLogger.debug("EcdsaSignatureFixNeeded: {}", b);
        }

        if (b == null || b) {
          byte[] fixedSigValue;
          if (signVerifyExtraParams != null) {
            int rOrSLen = (signVerifyExtraParams.ecOrderBitSize() + 7) / 8;
            fixedSigValue = Functions.fixECDSASignature(signatureValue, rOrSLen);
          } else {
            // get the ecParams
            byte[] ecParams;
            try {
              ecParams = getAttrValues(signOrVerifyKeyHandle, CKA_EC_PARAMS).ecParams();
            } catch (PKCS11Exception e) {
              StaticLogger.debug("error getting CKA_EC_PARAMS for key {}", signOrVerifyKeyHandle);
              return signatureValue;
            }

            if (ecParams == null) {
              StaticLogger.debug("found no CKA_EC_PARAMS for key {}", signOrVerifyKeyHandle);
              return signatureValue;
            }

            fixedSigValue = Functions.fixECDSASignature(signatureValue, ecParams);
          }

          boolean fixed = !Arrays.equals(fixedSigValue, signatureValue);
          if (b == null) {
            StaticLogger.info("Set EcdsaSignatureFixNeeded to {}", fixed);
            module.setEcdsaSignatureFixNeeded(fixed);
          }
          return fixedSigValue;
        }
      } else if (signatureType == SIGN_TYPE_SM2) {
        Boolean b = module.getSm2SignatureFixNeeded();
        if (b == null) {
          StaticLogger.info("Sm2SignatureFixNeeded: null");
        } else {
          StaticLogger.debug("Sm2SignatureFixNeeded: {}", b);
        }

        if (b == null || b) {
          byte[] fixedSigValue = Functions.fixECDSASignature(signatureValue, 32);
          boolean fixed = !Arrays.equals(fixedSigValue, signatureValue);
          if (b == null) {
            StaticLogger.info("Set Sm2SignatureFixNeeded to {}", fixed);
            module.setSm2SignatureFixNeeded(fixed);
          }
          return fixedSigValue;
        }
      }

      return signatureValue;
    }
  }

  private byte[] fixSignatureToVerify(byte[] signatureValue) {
    if (signatureType == SIGN_TYPE_ECDSA) {
      if (module.hasVendorBehaviour(PKCS11Module.BEHAVIOUR_ECDSA_SIGNATURE_X962)) {
        return Functions.dsaSigPlainToX962(signatureValue);
      }
    } else if (signatureType == SIGN_TYPE_SM2) {
      if (module.hasVendorBehaviour(PKCS11Module.BEHAVIOUR_SM2_SIGNATURE_X962)) {
        return Functions.dsaSigPlainToX962(signatureValue);
      }
    }

    return signatureValue;
  }

  /**
   * Initializes a new signing operation for signing with recovery. The application must call this
   * method before calling signRecover. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechanism to use for signing
   * and the key for this operation. The key must have set its sign-recover flag. For the mechanism
   * the application may use a constant defined in the Mechanism class. Notice that the key and the
   * mechanism must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.RSA_9796.
   * @param keyHandle The signing key to use.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void signRecoverInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    final String method = "C_SignRecoverInit";
    mechanism.setModule(module);
    debugIn(method, "keyHandle={}, mechanism={}", keyHandle, mechanism);
    try {
      pkcs11.C_SignRecoverInit(sessionHandle, mechanism.toCkMechanism(), keyHandle);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Signs the given data with the key and mechanism given to the signRecoverInit method. This
   * method finalizes the current sign-recover operation; there is no equivalent method to
   * signUpdate for signing with recovery.
   *
   * @param in     buffer containing the to-be-signed data
   * @param out    buffer for the signed data
   * @return the length of signed data
   * @throws PKCS11Exception If signing the data failed.
   */
  public int signRecover(byte[] in, byte[] out) throws PKCS11Exception {
    return signRecover(in, 0, in.length, out, 0, out.length);
  }

  public int signRecoverSingle(Mechanism mechanism, long keyHandle, byte[] in, byte[] out) throws PKCS11Exception {
    signRecoverInit(mechanism, keyHandle);
    return signRecoverSingle(mechanism, keyHandle, in, 0, in.length, out, 0, out.length);
  }

  /**
   * Signs the given data with the key and mechanism given to the signRecoverInit method. This
   * method finalizes the current sign-recover operation; there is no equivalent method to
   * signUpdate for signing with recovery.
   *
   * @param in     buffer containing the to-be-signed data
   * @param inOfs  buffer offset of the to-be-signed data
   * @param inLen  length of the to-be-signed data
   * @param out    buffer for the signed data
   * @param outOfs buffer offset for the signed data
   * @param outLen buffer size for the signed data
   * @return the length of signed data
   * @throws PKCS11Exception If signing the data failed.
   */
  public int signRecover(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    final String method = "C_SignRecover";
    checkParams(in, inOfs, inLen, out, outOfs, outLen);
    debugIn(method, "inOfs={}, inLen={}, outOfs={}, outLen", inOfs, inLen, outOfs, outLen);
    try {
      return logOutLen(method, pkcs11.C_SignRecover(sessionHandle, in, inOfs, inLen, out, outOfs, outLen));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  public int signRecoverSingle(Mechanism mechanism, long keyHandle, byte[] in, int inOfs, int inLen,
                         byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    signRecoverInit(mechanism, keyHandle);
    return signRecover(in, inOfs, inLen, out, outOfs, outLen);
  }

  /**
   * Initializes a new verification operation. You can use it for verifying signatures and MACs. The
   * application must call this method before calling any other verify* operation. Before
   * initializing a new operation, any currently pending operation must be finalized using the
   * appropriate *Final method (e.g. digestFinal()). There are exceptions for dual-function
   * operations. This method requires the mechanism to use for verification and the key for this
   * operation. The key must have set its verify flag. For the mechanism the application may use a
   * constant defined in the Mechanism class. Notice that the key and the mechanism must be
   * compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param keyHandle The verification key to use.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void verifyInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    final String method = "C_VerifyInit";
    mechanism.setModule(module);
    try {
      initSignVerify(mechanism, keyHandle);
      debugIn(method, "keyHandle={}, mechanism={}", keyHandle, mechanism);
      pkcs11.C_VerifyInit(sessionHandle, mechanism.toCkMechanism(), keyHandle);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Verifies the given signature against the given data with the key and mechanism given to the
   * verifyInit method. This method finalizes the current verification operation; i.e. the
   * application need (and should) not call verifyFinal() after this call. For verifying with
   * multiple pieces of data use verifyUpdate and verifyFinal. This method throws an exception, if
   * the verification of the signature fails.
   *
   * @param data      The data that was signed.
   * @param signature The signature or MAC to verify.
   * @throws PKCS11Exception If verifying the signature fails. This is also the case, if the signature is
   *                         forged.
   */
  public void verify(byte[] data, byte[] signature) throws PKCS11Exception {
    final String method = "C_Verify";
    Functions.requireNonNull("signature", signature);
    debugIn(method, "data.length={}, signature.length={}", len(data), len(signature));
    try {
      pkcs11.C_Verify(sessionHandle, data, fixSignatureToVerify(signature));
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  public void verifySingle(Mechanism mechanism, long keyHandle, byte[] data, byte[] signature) throws PKCS11Exception {
    verifyInit(mechanism, keyHandle);
    verify(data, signature);
  }

  /**
   * This method can be used to verify a signature with multiple pieces of data; e.g. buffer-size
   * pieces when reading the data from a stream. To verify the signature or MAC call verifyFinal
   * after feeding in all data using this method.
   *
   * @param in    the to-be-verified data
   * @throws PKCS11Exception If verifying (e.g. digesting) the data failed.
   */
  public void verifyUpdate(byte[] in) throws PKCS11Exception {
    verifyUpdate(in, 0, in.length);
  }

  /**
   * This method can be used to verify a signature with multiple pieces of data; e.g. buffer-size
   * pieces when reading the data from a stream. To verify the signature or MAC call verifyFinal
   * after feeding in all data using this method.
   *
   * @param in    buffer containing the to-be-verified data
   * @param inOfs buffer offset of the to-be-verified data
   * @param inLen length of the to-be-verified data
   * @throws PKCS11Exception If verifying (e.g. digesting) the data failed.
   */
  public void verifyUpdate(byte[] in, int inOfs, int inLen) throws PKCS11Exception {
    final String method = "C_VerifyUpdate";
    checkInParams(in, inOfs, inLen);
    debugIn(method, "inOfs={}, inLen={}", inOfs, inLen);

    try {
      pkcs11.C_VerifyUpdate(sessionHandle, 0, in, inOfs, inLen);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * This method finalizes a verification operation. Use this method, if you fed in the data using
   * verifyUpdate. If you used the verify(byte[]) method, you need not (and shall not) call this
   * method, because verify(byte[]) finalizes the verification operation itself. If this method
   * verified the signature successfully, it returns normally. If the verification of the signature
   * fails, e.g. if the signature was forged or the data was modified, this method throws an
   * exception.
   *
   * @param signature The signature value.
   * @throws PKCS11Exception If verifying the signature fails. This is also the case, if the signature is
   *                         forged.
   */
  public void verifyFinal(byte[] signature) throws PKCS11Exception {
    final String method = "C_VerifyFinal";
    Functions.requireNonNull("signature", signature);
    debugIn(method, "signature.length={}", len(signature));
    try {
      pkcs11.C_VerifyFinal(sessionHandle, fixSignatureToVerify(signature));
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Initializes a new verification operation for verification with data recovery. The application
   * must call this method before calling verifyRecover. Before initializing a new operation, any
   * currently pending operation must be finalized using the appropriate *Final method (e.g.
   * digestFinal()). This method requires the mechanism to use for verification and the key for this
   * operation. The key must have set its verify-recover flag. For the mechanism the application may
   * use a constant defined in the Mechanism class. Notice that the key and the mechanism must be
   * compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.RSA_9796.
   * @param keyHandle The verification key to use.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void verifyRecoverInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    final String method = "C_VerifyRecoverInit";
    mechanism.setModule(module);
    debugIn(method, "keyHandle={}, mechanism={}", keyHandle, mechanism);
    try {
      pkcs11.C_VerifyRecoverInit(sessionHandle, mechanism.toCkMechanism(), keyHandle);
      debugOut(method);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Verifies the given data with the key and mechanism given to the verifyRecoverInit method. This
   * method finalizes the current verify-recover operation; there is no equivalent method to
   * verifyUpdate for signing with recovery.
   *
   * @param in
   *          the to-be-verified data
   * @param out
   *          the verified data
   * @return the length of verified data
   * @exception PKCS11Exception
   *              If signing the data failed.
   */
  public int verifyRecover(byte[] in, byte[] out) throws PKCS11Exception {
    return verifyRecover(in, 0, in.length, out, 0, out.length);
  }

  public int verifyRecoverSingle(Mechanism mechanism, long keyHandle, byte[] in, byte[] out) throws PKCS11Exception {
    verifyRecoverInit(mechanism, keyHandle);
    return verifyRecoverSingle(mechanism, keyHandle, in, 0, in.length, out, 0, out.length);
  }

  /**
   * Verifies the given data with the key and mechanism given to the verifyRecoverInit method. This
   * method finalizes the current verify-recover operation; there is no equivalent method to
   * verifyUpdate for signing with recovery.
   *
   * @param in
   *          buffer containing the to-be-verified data
   * @param inOfs
   *          buffer offset of the to-be-verified data
   * @param inLen
   *          length of the to-be-verified data
   * @param out
   *          buffer for the verified data
   * @param outOfs
   *          buffer offset for the verified data
   * @param outLen
   *          buffer size for the verified data
   * @return the length of verified data
   * @exception PKCS11Exception
   *              If signing the data failed.
   */
  public int verifyRecover(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkParams(in, inOfs, inLen, out, outOfs, outLen);
    final String method = "C_VerifyRecover";
    debugIn(method, "inOfs={}, inLen={}, outOfs={}, outLen", inOfs, inLen, outOfs, outLen);
    try {
      return logOutLen(method, pkcs11.C_VerifyRecover(sessionHandle, in, inOfs, inLen, out, outOfs, outLen));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  public int verifyRecoverSingle(Mechanism mechanism, long keyHandle, byte[] in, int inOfs, int inLen,
                           byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    verifyRecoverInit(mechanism, keyHandle);
    return verifyRecover(in, inOfs, inLen, out, outOfs, outLen);
  }

  /**
  /**
   * Generate a new secret key or a set of domain parameters. It uses the set attributes of the
   * template for setting the attributes of the new key object. As mechanism the application can use
   * a constant of the Mechanism class.
   *
   * @param mechanism
   *          The mechanism to generate a key for; e.g. Mechanism.DES to generate a DES key.
   * @param template
   *          The template for the new key or domain parameters; e.g. a DESSecretKey object which
   *          has set certain attributes.
   * @return The newly generated secret key or domain parameters.
   * @exception PKCS11Exception
   *              If generating a new secret key or domain parameters failed.
   */
  public long generateKey(Mechanism mechanism, AttributeVector template) throws PKCS11Exception {
    final String method = "C_GenerateKey";
    mechanism.setModule(module);
    debugIn(method, "mechanism={}, template={}", mechanism, template);
    try {
      long hKey = pkcs11.C_GenerateKey(sessionHandle, mechanism.toCkMechanism(), toOutCKAttributes(template));
      debugOut(method, "hKey={}", hKey);
      traceObject("generated key", hKey);
      return hKey;
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Generate a new public key - private key key-pair and use the set attributes of the template
   * objects for setting the attributes of the new public key and private key objects. As mechanism
   * the application can use a constant of the Mechanism class.
   *
   * @param mechanism
   *          The mechanism to generate a key for; e.g. Mechanism.RSA to generate a new RSA
   *          key-pair.
   * @param template
   *          The template for the new key pair.
   * @return The newly generated key-pair.
   * @exception PKCS11Exception
   *              If generating a new key-pair failed.
   */
  public PKCS11KeyPair generateKeyPair(Mechanism mechanism, KeyPairTemplate template) throws PKCS11Exception {
    final String method = "C_GenerateKeyPair";
    mechanism.setModule(module);
    debugIn(method, "mechanism={}, template={}", mechanism, template);
    long[] objectHandles;
    try {
      objectHandles = pkcs11.C_GenerateKeyPair(sessionHandle, mechanism.toCkMechanism(),
          toOutCKAttributes(template.publicKey()), toOutCKAttributes(template.privateKey()));
      PKCS11KeyPair rv = new PKCS11KeyPair(objectHandles[0], objectHandles[1]);
      debugOut("C_GenerateKeyPair", "hPublicKey={}, hPrivateKey={}",
          rv.getPublicKey(), rv.getPrivateKey());
      traceObject("public  key of the generated keypair", rv.getPublicKey());
      traceObject("private key of the generated keypair", rv.getPrivateKey());
      return rv;
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Wraps (encrypts) the given key with the wrapping key using the given mechanism.
   *
   * @param mechanism
   *          The mechanism to use for wrapping the key.
   * @param wrappingKeyHandle
   *          The key to use for wrapping (encrypting).
   * @param keyHandle
   *          The key to wrap (encrypt).
   * @return The wrapped key as byte array.
   * @exception PKCS11Exception
   *              If wrapping the key failed.
   */
  public byte[] wrapKey(Mechanism mechanism, long wrappingKeyHandle, long keyHandle) throws PKCS11Exception {
    final String method = "C_WrapKey";
    mechanism.setModule(module);
    debugIn(method, "wrappingKeyHandle={}, keyHandle={}, mechanism={}", wrappingKeyHandle, keyHandle, mechanism);
    try {
      return toNonNull(method,
              pkcs11.C_WrapKey(sessionHandle, mechanism.toCkMechanism(), wrappingKeyHandle, keyHandle));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Unwraps (decrypts) the given encrypted key with the unwrapping key using the given mechanism.
   * The application can also pass a template key to set certain attributes of the unwrapped key.
   * This creates a key object after unwrapping the key and returns an object representing this key.
   *
   * @param mechanism
   *          The mechanism to use for unwrapping the key.
   * @param unwrappingKeyHandle
   *          The key to use for unwrapping (decrypting).
   * @param wrappedKey
   *          The encrypted key to unwrap (decrypt).
   * @param keyTemplate
   *          The template for creating the new key object.
   * @return A key object representing the newly created key object.
   * @exception PKCS11Exception
   *              If unwrapping the key or creating a new key object failed.
   */
  public long unwrapKey(Mechanism mechanism, long unwrappingKeyHandle,
                        byte[] wrappedKey, AttributeVector keyTemplate) throws PKCS11Exception {
    Functions.requireNonNull("wrappedKey", wrappedKey);
    final String method = "C_UnwrapKey";
    mechanism.setModule(module);
    debugIn(method, "unwrappingKeyHandle={}, wrappedKey.length={}, mechanism={}, template={}",
        unwrappingKeyHandle, len(wrappedKey), mechanism, keyTemplate);

    try {
      long hKey = pkcs11.C_UnwrapKey(sessionHandle, mechanism.toCkMechanism(),
          unwrappingKeyHandle, wrappedKey, toOutCKAttributes(keyTemplate));
      debugOut(method, "hKey={}", hKey);
      traceObject("unwrapped key", hKey);
      return hKey;
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Derives a new key from a specified base key using the given mechanism.
   * After deriving a new key from the base key, a new key object is created
   * and a representation of it is returned. The application can provide a
   * template key to set certain attributes of the new key object.
   *
   * @param mechanism
   *          The mechanism to use for deriving the new key from the base key.
   * @param baseKeyHandle
   *          The key to use as base for derivation.
   * @param template
   *          The template for creating the new key object.
   * @return A key object representing the newly derived (created) key object
   *         or null, if the used mechanism uses other means to return its
   *         values; e.g. the CKM_SSL3_KEY_AND_MAC_DERIVE mechanism.
   * @exception PKCS11Exception
   *              If deriving the key or creating a new key object failed.
   */
  public long deriveKey(Mechanism mechanism, long baseKeyHandle, AttributeVector template) throws PKCS11Exception {
    final String method = "C_DeriveKey";
    mechanism.setModule(module);
    debugIn(method, "baseKeyHandle={}, mechanism={},template={}", baseKeyHandle, mechanism, template);

    try {
      long hKey = pkcs11.C_DeriveKey(sessionHandle, mechanism.toCkMechanism(), baseKeyHandle,
                    toOutCKAttributes(template));
      debugOut(method, "hKey={}", hKey);
      traceObject("derived key", hKey);
      return hKey;
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    }
  }

  /**
   * Mixes additional seeding material into the random number generator.
   *
   * @param seed
   *          The seed bytes to mix in.
   * @exception PKCS11Exception
   *              If mixing in the seed failed.
   */
  public void seedRandom(byte[] seed) throws PKCS11Exception {
    try {
      pkcs11.C_SeedRandom(sessionHandle, seed);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw module.convertException(ex);
    }
  }

  /**
   * Generates a certain number of random bytes.
   *
   * @param numberOfBytesToGenerate
   *          The number of random bytes to generate.
   * @return An array of random bytes with length numberOfBytesToGenerate.
   * @exception PKCS11Exception
   *              If generating random bytes failed.
   */
  public byte[] generateRandom(int numberOfBytesToGenerate) throws PKCS11Exception {
    final String method = "C_GenerateRandom";
    debugIn(method, "numberOfBytesToGenerate={}", numberOfBytesToGenerate);
    byte[] randomBytesBuffer = new byte[numberOfBytesToGenerate];
    try {
      pkcs11.C_GenerateRandom(sessionHandle, randomBytesBuffer);
      return toNonNull("C_GenerateRandom", randomBytesBuffer);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      debugError(method, ex);
      throw module.convertException(ex);
    } // fill the buffer with random bytes
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return "Session Handle: 0x" + Long.toHexString(sessionHandle) +  "\nToken: " + token;
  }

  public String getStringAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    CharArrayAttribute attr = new CharArrayAttribute(attributeType);
    doGetAttrValue(objectHandle, attr);
    return attr.getValue();
  }

  public Object getAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    Attribute attr = Attribute.getInstance(attributeType);
    doGetAttrValue(objectHandle, attr);
    return attr.getValue();
  }

  public AttributeVector getAttrValues(long objectHandle, long... attributeTypes) throws PKCS11Exception {
    List<Long> typeList = new ArrayList<>(attributeTypes.length);
    for (long attrType : attributeTypes) {
      typeList.add(attrType);
    }
    return getAttrValues(objectHandle, typeList);
  }

  public AttributeVector getAttrValues(long objectHandle, List<Long> attributeTypes) throws PKCS11Exception {
    if (attributeTypes.contains(CKA_EC_POINT)
        && !attributeTypes.contains(CKA_EC_PARAMS)) {
      synchronized (module) {
        Boolean b = module.getEcPointFixNeeded();
        if (b == null || b) {
          attributeTypes.add(CKA_EC_PARAMS);
        }
      }
    }

    Attribute[] attrs = new Attribute[attributeTypes.size()];
    int index = 0;

    // we need to fix attributes EC_PARAMS and EC_POINT. Where EC_POINT needs EC_PARAMS,
    // and EC_PARAMS needs KEY_TYPE.
    long[] firstTypes = {CKA_CLASS, CKA_KEY_TYPE, CKA_EC_PARAMS, CKA_EC_POINT};

    for (long type : firstTypes) {
      if (attributeTypes.remove(type)) {
        attrs[index++] =  Attribute.getInstance(type);
      }
    }

    for (long type : attributeTypes) {
      attrs[index++] =  Attribute.getInstance(type);
    }

    doGetAttrValues(objectHandle, attrs);
    return new AttributeVector(attrs);
  }

  /**
   * Return the default attributes, but without attributes which contain the sensitive values.
   * @param objectHandle the object handle.
   * @return the attributes.
   * @throws PKCS11Exception If getting attributes failed.
   */
  public AttributeVector getDefaultAttrValues(long objectHandle) throws PKCS11Exception {
    return getDefaultAttrValues(objectHandle, false);
  }

  /**
   * Return the default attributes
   * @param objectHandle the object handle.
   * @param withSensitiveVAttributes whether to get the attributes which contain sensitive values.
   * @return the attributes.
   * @throws PKCS11Exception If getting attributes failed.
   */
  public AttributeVector getDefaultAttrValues(long objectHandle, boolean withSensitiveVAttributes)
      throws PKCS11Exception {
    long objClass = getAttrValues(objectHandle, CKA_CLASS).class_();
    List<Long> ckaTypes = new LinkedList<>();
    addCkaTypes(ckaTypes, CKA_LABEL, CKA_ID, CKA_TOKEN);

    if (objClass == CKO_SECRET_KEY || objClass == CKO_PRIVATE_KEY) {
      addCkaTypes(ckaTypes, CKA_ALLOWED_MECHANISMS, CKA_DECRYPT, CKA_EXTRACTABLE, CKA_KEY_GEN_MECHANISM,
          CKA_NEVER_EXTRACTABLE, CKA_PRIVATE, CKA_SIGN, CKA_UNWRAP, CKA_UNWRAP_TEMPLATE, CKA_WRAP_WITH_TRUSTED);

      AttributeVector attrs = getAttrValues(objectHandle, CKA_KEY_TYPE, CKA_SENSITIVE, CKA_ALWAYS_SENSITIVE);
      long keyType = attrs.keyType();
      Boolean sensitive = attrs.sensitive();
      Boolean alwaysSensitive = attrs.alwaysSensitive();

      boolean withSensitiveAttrs = withSensitiveVAttributes;
      if (withSensitiveAttrs) {
        boolean isSensitive = (sensitive == null) || sensitive;
        if (alwaysSensitive != null) {
          isSensitive |= alwaysSensitive;
        }
        withSensitiveAttrs = !isSensitive;
      }

      if (objClass == CKO_SECRET_KEY) {
        addCkaTypes(ckaTypes, CKA_ENCRYPT, CKA_TRUSTED, CKA_VERIFY, CKA_WRAP, CKA_WRAP_TEMPLATE);

        if (!(keyType == CKK_DES || keyType == CKK_DES2 || keyType == CKK_DES3)) {
          ckaTypes.add(CKA_VALUE_LEN);
        }

        if (withSensitiveAttrs) {
          ckaTypes.add(CKA_VALUE);
        }
      } else {
        addCkaTypes(ckaTypes, CKA_ALWAYS_AUTHENTICATE, CKA_SIGN_RECOVER);

        if (keyType == CKK_RSA) {
          addCkaTypes(ckaTypes, CKA_MODULUS, CKA_PUBLIC_EXPONENT);
          if (withSensitiveAttrs) {
            addCkaTypes(ckaTypes, CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2,
                CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT);
          }
        } else if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY
            || keyType == CKK_VENDOR_SM2) {
          ckaTypes.add(CKA_EC_PARAMS);
          if (withSensitiveAttrs) {
            ckaTypes.add(CKA_VALUE);
          }
        } else if (keyType == CKK_DSA) {
          addCkaTypes(ckaTypes, CKA_PRIME, CKA_SUBPRIME, CKA_BASE);
          if (withSensitiveAttrs) {
            ckaTypes.add(CKA_VALUE);
          }
        }
      }

      return getAttrValues(objectHandle, ckaTypes).class_(objClass).keyType(keyType)
          .sensitive(sensitive).alwaysSensitive(alwaysSensitive);
    } else if (objClass == CKO_PUBLIC_KEY) {
      addCkaTypes(ckaTypes, CKA_ALLOWED_MECHANISMS, CKA_ENCRYPT, CKA_KEY_GEN_MECHANISM, CKA_TRUSTED,
          CKA_VERIFY, CKA_VERIFY_RECOVER, CKA_WRAP, CKA_WRAP_TEMPLATE);
      long keyType = getAttrValues(objectHandle, CKA_KEY_TYPE).keyType();
      if (keyType == CKK_RSA) {
        addCkaTypes(ckaTypes, CKA_MODULUS, CKA_PUBLIC_EXPONENT);
      } else if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY
          || keyType == CKK_VENDOR_SM2) {
        addCkaTypes(ckaTypes, CKA_EC_PARAMS, CKA_EC_POINT);
      } else if (keyType == CKK_DSA) {
        addCkaTypes(ckaTypes, CKA_PRIME, CKA_SUBPRIME, CKA_BASE);
      }

      return getAttrValues(objectHandle, ckaTypes).class_(objClass).keyType(keyType);
    } else if (objClass == CKO_CERTIFICATE) {
      addCkaTypes(ckaTypes, CKA_TRUSTED, CKA_CERTIFICATE_CATEGORY, CKA_START_DATE, CKA_END_DATE);
      long certType = getAttrValues(objectHandle, CKA_CERTIFICATE_TYPE).certificateType();
      if (certType == CKC_X_509) {
        addCkaTypes(ckaTypes, CKA_VALUE, CKA_URL, CKA_ISSUER, CKA_SUBJECT, CKA_SERIAL_NUMBER,
            CKA_HASH_OF_ISSUER_PUBLIC_KEY, CKA_HASH_OF_SUBJECT_PUBLIC_KEY);
      }
      return getAttrValues(objectHandle, ckaTypes).class_(objClass).certificateType(certType);
    } else {
      return getAttrValues(objectHandle, ckaTypes);
    }
  }

  private static void addCkaTypes(List<Long> list, long... types) {
    for (long type : types) {
      list.add(type);
    }
  }

  /**
   * This method reads the attributes at once. This can lead  to performance
   * improvements. If reading all attributes at once fails, it tries to read
   * each attributes individually.
   *
   * @param objectHandle
   *          The handle of the object which contains the attributes.
   * @param attributes
   *          The objects specifying the attribute types
   *          (see {@link Attribute#getType()}) and receiving the attribute
   *          values (see {@link Attribute#ckAttribute(CK_ATTRIBUTE)}).
   * @exception PKCS11Exception
   *              If getting the attributes failed.
   */
  private void doGetAttrValues(long objectHandle, Attribute... attributes) throws PKCS11Exception {
    Functions.requireNonNull("attributes", attributes);

    if (attributes.length == 1) {
      doGetAttrValue(objectHandle, attributes[0]);
      return;
    }

    CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[attributes.length];
    for (int i = 0; i < attributes.length; i++) {
      attributeTemplateList[i] = new CK_ATTRIBUTE();
      attributeTemplateList[i].type = attributes[i].getType();
    }

    PKCS11Exception delayedEx = null;
    try {
      pkcs11.C_GetAttributeValue(sessionHandle, objectHandle, attributeTemplateList);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      delayedEx = module.convertException(ex);
    }

    for (int i = 0; i < attributes.length; i++) {
      Attribute attribute = attributes[i];
      CK_ATTRIBUTE template = attributeTemplateList[i];
      if (template != null) {
        attribute.present(true).sensitive(false).ckAttribute(template);
      }
    }

    if (delayedEx != null) {
      // do all failed separately again.
      delayedEx = null;
      for (Attribute attr : attributes) {
        if (attr.getCkAttribute() == null || attr.getCkAttribute().pValue == null) {
          try {
            doGetAttrValue0(objectHandle, attr, false);
          } catch (PKCS11Exception ex) {
            if (delayedEx == null) {
              delayedEx = ex;
            }
          }
        }
      }
    }

    for (Attribute attr : attributes) {
      postProcessGetAttribute(attr, objectHandle, attributes);
    }

    if (delayedEx != null) {
      throw delayedEx;
    }
  }

  /**
   * This method reads the attribute specified by <code>attribute</code> from
   * the token using the given <code>session</code>.
   * The object from which to read the attribute is specified using the
   * <code>objectHandle</code>. The <code>attribute</code> will contain
   * the results.
   * If the attempt to read the attribute returns
   * <code>CKR_ATTRIBUTE_TYPE_INVALID</code>, this will be indicated by
   * setting {@link Attribute#present(boolean)} to <code>false</code>.
   * It CKR_ATTRIBUTE_SENSITIVE is returned, the attribute object is
   * marked as present
   * (by calling {@link Attribute#present(boolean)} with
   * <code>true</code>), and in addition as sensitive by calling
   * {@link Attribute#sensitive(boolean)} with <code>true</code>.
   *
   * @param objectHandle
   *          The handle of the object which contains the attribute.
   * @param attribute
   *          The object specifying the attribute type
   *          (see {@link Attribute#getType()}) and receiving the attribute
   *          value (see {@link Attribute#ckAttribute(CK_ATTRIBUTE)}).
   * @exception PKCS11Exception
   *              If getting the attribute failed.
   */
  private void doGetAttrValue(long objectHandle, Attribute attribute)
      throws PKCS11Exception {
    if (attribute.getType() == CKA_EC_POINT) {
      doGetAttrValues(objectHandle, new ByteArrayAttribute(CKA_EC_PARAMS), attribute);
    } else {
      doGetAttrValue0(objectHandle, attribute, true);
    }
  }

  private void doGetAttrValue0(long objectHandle, Attribute attribute, boolean postProcess)
      throws PKCS11Exception {
    attribute.present(false);

    try {
      CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];
      attributeTemplateList[0] = new CK_ATTRIBUTE();
      attributeTemplateList[0].type = attribute.getType();
      pkcs11.C_GetAttributeValue(sessionHandle, objectHandle, attributeTemplateList);

      attribute.ckAttribute(attributeTemplateList[0]).present(true).sensitive(false);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      long ec = ex.getErrorCode();
      if (ec == CKR_ATTRIBUTE_TYPE_INVALID) {
        if (attribute.getType() == CKA_EC_PARAMS) {
          // this means, that some requested attributes are missing, but
          // we can ignore this and proceed; e.g. a v2.01 module won't
          // have the object ID attribute
          attribute.present(false).getCkAttribute().pValue = null;
        }
      } else if (ec == CKR_ATTRIBUTE_SENSITIVE) {
        // this means, that some requested attributes are missing, but
        // we can ignore this and proceed; e.g. a v2.01 module won't
        // have the object ID attribute
        attribute.getCkAttribute().pValue = null;
        attribute.present(true).sensitive(true).getCkAttribute().pValue = null;
      } else if (ec == CKR_ARGUMENTS_BAD || ec == CKR_FUNCTION_FAILED || ec == CKR_FUNCTION_REJECTED) {
        attribute.present(false).sensitive(false).getCkAttribute().pValue = null;
      } else {
        // there was a different error that we should propagate
        throw module.convertException(ex);
      }
    }

    if (postProcess) {
      postProcessGetAttribute(attribute, objectHandle);
    }
  }

  private CK_ATTRIBUTE[] toOutCKAttributes(AttributeVector template) {
    return toOutCKAttributes(template, false);
  }

  private CK_ATTRIBUTE[] toOutCKAttributes(AttributeVector template, boolean withoutNullValueAttr) {
    if (template == null) {
      return null;
    }

    CK_ATTRIBUTE[] ckAttrs = template.toCkAttributes();
    List<CK_ATTRIBUTE> nonNullCkAttrs = null;
    if (withoutNullValueAttr) {
      nonNullCkAttrs = new ArrayList<>(ckAttrs.length);
    }

    for (CK_ATTRIBUTE ckAttr : ckAttrs) {
      if (ckAttr.pValue == null) {
        continue;
      } else {
        if (withoutNullValueAttr) {
          nonNullCkAttrs.add(ckAttr);
        }
      }

      if (ckAttr.type == CKA_KEY_TYPE) {
        long value = (long) ckAttr.pValue;
        ckAttr.pValue = module.genericToVendorCode(Category.CKK, value);
      } else if (ckAttr.type == CKA_EC_POINT) {
        boolean isBitString = false;
        Attribute attr = template.getAttribute(CKA_KEY_TYPE);
        if (attr != null) {
          long keyType = (long) attr.getValue();
          isBitString = (keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY);
        }

        ckAttr.pValue = Functions.toOctetOrBitString((byte[]) ckAttr.pValue, isBitString);
      } else if (ckAttr.type == CKA_EC_PARAMS) {
        byte[] pValue = (byte[]) ckAttr.pValue;
        byte[] newPValue = null;
        if (module.hasVendorBehaviour(PKCS11Module.BEHAVIOUR_EC_PARAMS_NAME_ONLY_EDWARDS)) {
          newPValue = Arrays.equals(OID_edwards25519, pValue) ? NAME_edwards25519
              : Arrays.equals(OID_edwards448, pValue) ? NAME_edwards448 : null;
        } else if (module.hasVendorBehaviour(PKCS11Module.BEHAVIOUR_EC_PARAMS_NAME_ONLY_MONTGOMERY)) {
          newPValue = Arrays.equals(OID_curve25519, pValue) ? NAME_curve25519
              : Arrays.equals(OID_curve448, pValue) ? NAME_curve448 : null;
        }

        if (newPValue != null) {
          ckAttr.pValue = Arrays.copyOf(newPValue, newPValue.length);
        }
      }
    }

    return nonNullCkAttrs != null && nonNullCkAttrs.size() != ckAttrs.length
        ? nonNullCkAttrs.toArray(new CK_ATTRIBUTE[0]) : ckAttrs;
  }

  private void postProcessGetAttribute(Attribute attr, long objectHandle, Attribute... otherAttrs) {
    long type = attr.getType();
    CK_ATTRIBUTE ckAttr = attr.getCkAttribute();

    if (type == CKA_EC_PARAMS) {
      if (ckAttr.pValue == null) {
        // Some HSMs do not return EC_PARAMS
        Long keyType = null;
        if (otherAttrs != null) {
          for (Attribute otherAttr : otherAttrs) {
            if (otherAttr.type() == CKA_KEY_TYPE) {
              keyType = ((LongAttribute) otherAttr).getValue();
            }
          }
        }

        if (keyType == null) {
          try {
            keyType = getAttrValues(objectHandle, CKA_KEY_TYPE).keyType();
          } catch (PKCS11Exception e2) {
          }
        }

        if (keyType != null && keyType == CKK_VENDOR_SM2) {
          attr.present(false).getCkAttribute().pValue = Functions.decodeHex("06082a811ccf5501822d");
        }
      } else {
        byte[] ecParams = (byte[]) ckAttr.pValue;
        if (ecParams[0] != 0x06) { // 06: OBJECT IDENTIFIER
          ckAttr.pValue = Functions.fixECParams((byte[]) ckAttr.pValue);
        }
      }

      return;
    }

    if (ckAttr == null || ckAttr.pValue == null) {
      return;
    }

    if (type == CKA_KEY_TYPE) {
      long value = (long) ckAttr.pValue;
      if (!isUnavailableInformation(value)) {
        ckAttr.pValue = module.vendorToGenericCode(Category.CKK, value);
      }
    } else if (type == CKA_KEY_GEN_MECHANISM) {
      long value = (long) ckAttr.pValue;
      if (!isUnavailableInformation(value)) {
        ckAttr.pValue = module.vendorToGenericCode(Category.CKM, value);
      }
    } else if (type == CKA_ALLOWED_MECHANISMS) {
      long[] mechs = ((MechanismArrayAttribute) attr).getValue();
      for (long mech : mechs) {
        ckAttr.pValue = module.vendorToGenericCode(Category.CKM, mech);
      }
    } else if (type == CKA_EC_POINT) {
      Boolean b = module.getEcPointFixNeeded();
      byte[] pValue = (byte[]) ckAttr.pValue;

      if (b == null || b) {
        byte[] ecParams = null;
        if (otherAttrs != null) {
          for (Attribute otherAttr : otherAttrs) {
            if (otherAttr.getType() == CKA_EC_PARAMS) {
              ecParams = ((ByteArrayAttribute) otherAttr).getValue();
              break;
            }
          }
        }

        byte[] fixedCoreEcPoint = Functions.getCoreECPoint(pValue, ecParams);
        if (b == null) {
          byte[] coreEcPoint = Functions.getCoreECPoint(pValue);
          module.setEcPointFixNeeded(!Arrays.equals(coreEcPoint, fixedCoreEcPoint));
        }
        ckAttr.pValue = fixedCoreEcPoint;
      } else {
        ckAttr.pValue = Functions.getCoreECPoint(pValue);
      }
    } else if (attr instanceof BooleanAttribute) {
      if (ckAttr.pValue instanceof byte[]) {
        byte[] value = (byte[]) ckAttr.pValue;
        boolean allZeros = true;
        for (byte b : value) {
          if (b != 0) {
            allZeros = false;
            break;
          }
        }
        ckAttr.pValue = !allZeros;
      }
    }
  }

  private static void checkParams(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) {
    checkInParams(in, inOfs, inLen);
    checkOutParams(out, outOfs, outLen);
  }

  private static void checkInParams(byte[] in, int inOfs, int inLen) {
    Functions.requireNonNull("in", in);
    if (inOfs < 0 || inLen <= 0) {
      throw new IllegalArgumentException("inOfs or inLen is invalid");
    }
    if (in.length < inOfs + inLen) {
      throw new IllegalArgumentException("inOfs + inLen > in.length");
    }
  }

  private static void checkOutParams(byte[] out, int outOfs, int outLen) {
    Functions.requireNonNull("out", out);
    if (outOfs < 0 || outLen <= 0) {
      throw new IllegalArgumentException("outOfs or outLen is invalid");
    }
    if (out.length < outOfs + outLen) {
      throw new IllegalArgumentException("outOfs + outLen > out.length");
    }
  }

  private void debugIn(String cMethod) {
    if (StaticLogger.isDebugEnabled()) {
      StaticLogger.debug("IN  " + cMethod + ": hSession=" + sessionHandle);
    }
  }

  private void debugIn(String method, String format, Object... arguments) {
    if (StaticLogger.isDebugEnabled()) {
      StaticLogger.debug("IN  " + method + ": hSession=" + sessionHandle + ", " + format, arguments);
    }
  }

  private void debugError(String method) {
    if (StaticLogger.isDebugEnabled()) {
      StaticLogger.debug(method + ": hSession=" + sessionHandle);
    }
  }

  private void debugError(String method, sun.security.pkcs11.wrapper.PKCS11Exception e) {
    if (StaticLogger.isDebugEnabled()) {
      StaticLogger.debug("ERR " + method + ": " + module.codeToName(Category.CKR, e.getErrorCode()));
    }
  }

  private void debugOut(String method) {
    if (StaticLogger.isDebugEnabled()) {
      StaticLogger.debug("OUT " + method + ": hSession=" + sessionHandle);
    }
  }

  private void debugOut(String method, String format, Object... arguments) {
    if (StaticLogger.isDebugEnabled()) {
      StaticLogger.debug("OUT " + method + ": hSession=" + sessionHandle + ", " + format, arguments);
    }
  }

  private static int len(byte[] bytes) {
    return bytes == null ? 0 : bytes.length;
  }

  private byte[] toNonNull(String method, byte[] bytes) {
    if (bytes == null) {
      debugOut(method, "rv=null");
    } else {
      debugOut(method, "rv.length={}", bytes.length);
    }

    return (bytes == null) ? new byte[0] : bytes;
  }

  private int logOutLen(String method, int outLen) {
    debugOut(method, "outLen={}", outLen);
    return outLen;
  }

  private byte[] toNonNull(byte[] bytes) {
    return (bytes == null) ? new byte[0] : bytes;
  }

  private void traceObject(String prefix, long hObject) {
    if (StaticLogger.isTraceEnabled()) {
      try {
        StaticLogger.trace(prefix + ": handle=" + hObject + ", attributes\n" + getDefaultAttrValues(hObject));
      } catch (PKCS11Exception e) {
        StaticLogger.trace(prefix + ": reading object " + hObject + " failed with " + ckrCodeToName(e.getErrorCode()));
      }
    }
  }

}
