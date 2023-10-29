// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.xipki.pkcs11.wrapper.ConcurrentBag.BagEntry;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PublicKey;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This is a PKCS#11 token with session management.
 *
 * @author xipki
 */
public class PKCS11Token {

  private enum OP {
    DIGEST,
    SIGN,
    VERIFY,
    ENCRYPT,
    DECRYPT,
    SIGN_RECOVER,
    VERIFY_RECOVER
  }

  private static final Clock clock = Clock.systemUTC();

  private int maxMessageSize = 2048;

  private final Token token;

  private final Map<Long, MechanismInfo> mechanisms = new HashMap<>();

  private final long userType;

  private final List<char[]> pins;

  private final int maxSessionCount;

  private final boolean readOnly;

  private long timeOutWaitNewSessionMs = 10000; // maximal wait for 10 second

  private final AtomicLong countSessions = new AtomicLong(0);

  private final ConcurrentBag<Session> sessions = new ConcurrentBag<>();

  private final Object loginSync = new Object();

  /**
   * The simple constructor.
   *
   * @param token    The token
   * @param readOnly True if this token is read only, false if read-write.
   * @param pin      The PIN of user type CKU_USER. May be null.
   * @throws TokenException If accessing the PKCS#11 device failed.
   */
  public PKCS11Token(Token token, boolean readOnly, char[] pin) throws TokenException {
    this(token, readOnly, CKU_USER, null, (pin == null ? null : Collections.singletonList(pin)), null);
  }

  /**
   * The advanced constructor.
   *
   * @param token       The token
   * @param readOnly    True if this token is read only, false if read-write.
   * @param userType    The user type. In general, it is CKU_USER.
   * @param userName    The user name. In this version, it must be null or empty.
   * @param pins        The PINs. May be null and empty list.
   * @param numSessions Number of sessions. May be null.
   * @throws TokenException If accessing the PKCS#11 device failed.
   */
  public PKCS11Token(Token token, boolean readOnly, long userType, char[] userName, List<char[]> pins,
                     Integer numSessions) throws TokenException {
    if (userName != null && userName.length != 0) {
      throw new IllegalArgumentException("userName is not null or empty");
    }

    if (numSessions != null && numSessions < 1) {
      throw new IllegalArgumentException("numSession is not valid: " + numSessions);
    }

    this.token = Objects.requireNonNull(token, "token shall not be null");
    this.readOnly = readOnly;
    this.userType = userType;
    this.pins = pins;

    TokenInfo tokenInfo = token.getTokenInfo();
    long lc = tokenInfo.getMaxSessionCount();
    int tokenMaxSessionCount = lc > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) lc;

    if (numSessions == null) {
      this.maxSessionCount = (tokenMaxSessionCount < 1) ? 32 : Math.min(32, tokenMaxSessionCount);
    } else {
      if (tokenMaxSessionCount < 1) {
        this.maxSessionCount = numSessions;
      } else {
        this.maxSessionCount = Math.min(numSessions, tokenMaxSessionCount);
      }
    }

    StaticLogger.info("tokenMaxSessionCount={}, maxSessionCount={}", tokenMaxSessionCount, this.maxSessionCount);

    for (long mech : token.getMechanismList()) {
      try {
        MechanismInfo mechInfo = token.getMechanismInfo(mech);
        mechanisms.put(mech, mechInfo);
      } catch (Exception e) {
        StaticLogger.warn("error getMechanism for {} (0x{}): {}",
            token.getSlot().getModule().codeToName(Category.CKM, mech), Functions.toFullHex(mech), e.getMessage());
      }
    }

    // login
    Session session = openSession();
    login(session);
    sessions.add(new BagEntry<>(session));
  }

  public PKCS11Module getModule() {
    return token.getSlot().getModule();
  }

  public void setTimeOutWaitNewSession(int timeOutWaitNewSessionMs) {
    if (timeOutWaitNewSessionMs < 1000) {
      throw new IllegalArgumentException("timeOutWaitNewSessionMs is not greater than 999");
    }
    this.timeOutWaitNewSessionMs = timeOutWaitNewSessionMs;
    StaticLogger.info("timeOutWaitNewSession = {} milli-seconds", timeOutWaitNewSessionMs);
  }

  /**
   * Sets the maximal message size sent to the PKCS#11 device in one command.
   *
   * @param maxMessageSize the maximal message size in bytes.
   */
  public void setMaxMessageSize(int maxMessageSize) {
    if (maxMessageSize < 256) {
      throw new IllegalArgumentException("maxMessageSize too small, at least 256 is required: " + maxMessageSize);
    }
    this.maxMessageSize = maxMessageSize % 16 * 16; // multiple of 16.
  }

  public Set<Long> getMechanisms() {
    return Collections.unmodifiableSet(mechanisms.keySet());
  }

  /**
   * Gets the {@link MechanismInfo} for given mechanism code.
   *
   * @param mechanism The mechanism code.
   * @return the {@link MechanismInfo}.
   */
  public MechanismInfo getMechanismInfo(long mechanism) {
    return mechanisms.get(mechanism);
  }

  /**
   * Returns whether the mechanism for given purpose is supported.
   *
   * @param mechanism The mechanism.
   * @param flagBit   The purpose. Valid values are (could be extended in the future PKCS#11 version):
   *                  {@link PKCS11Constants#CKF_SIGN}, {@link PKCS11Constants#CKF_VERIFY},
   *                  {@link PKCS11Constants#CKF_SIGN_RECOVER}, {@link PKCS11Constants#CKF_VERIFY_RECOVER},
   *                  {@link PKCS11Constants#CKF_ENCRYPT}, {@link PKCS11Constants#CKF_DECRYPT},
   *                  {@link PKCS11Constants#CKF_DERIVE}, {@link PKCS11Constants#CKF_DIGEST},
   *                  {@link PKCS11Constants#CKF_UNWRAP}, {@link PKCS11Constants#CKF_WRAP}.
   * @return whether mechanism with given flag bit is supported.
   */
  public boolean supportsMechanism(long mechanism, long flagBit) {
    MechanismInfo info = mechanisms.get(mechanism);
    return info != null && info.hasFlagBit(flagBit);
  }

  /**
   * Closes all sessions.
   */
  public void closeAllSessions() {
    if (token != null) {
      try {
        StaticLogger.info("close all sessions on token: {}", token.getTokenInfo());

        for (BagEntry<Session> session : sessions.values()) {
          session.value().closeSession();
        }
      } catch (Throwable th) {
        StaticLogger.error("error closing sessions, {}", th.getMessage());
      }
    }

    // clear the session pool
    sessions.close();
    countSessions.lazySet(0);
  }

  /**
   * Get the token (slot) identifier of this token.
   *
   * @return the slot identifier of this token.
   */
  public long getTokenId() {
    return token.getTokenID();
  }

  /**
   * Get the token that created this Session object.
   *
   * @return The token.
   */
  public Token getToken() {
    return token;
  }

  public String getModuleInfo() throws TokenException {
    return token.getSlot().getModule().getInfo().toString();
  }

  /**
   * Returns whether this token is read-only.
   *
   * @return true if read-only, false if read-write.
   */
  public boolean isReadOnly() {
    return readOnly;
  }

  /**
   * Login this session as CKU_SO (Security Officer).
   *
   * @param userName Username of user type CKU_SO. In this version, it must be null or empty.
   * @param pin      PIN.
   * @throws TokenException If logging in the session fails.
   */
  public void logInSecurityOfficer(char[] userName, char[] pin) throws TokenException {
    if (userName != null && userName.length != 0) {
      throw new IllegalArgumentException("userName is not null or empty");
    }

    BagEntry<Session> session0 = borrowNoLoginSession();
    Session session = session0.value();
    try {
      login(session, CKU_SO, (pin == null) ? null : Collections.singletonList(pin));
      StaticLogger.info("logIn CKU_SO");
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Logs out this session.
   *
   * @throws TokenException If logging out the session fails.
   */
  public void logout() throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      session.logout();
      StaticLogger.info("logout");
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Create a new object on the token (or in the session). The application must provide a template
   * that holds enough information to create a certain object. For instance, if the application
   * wants to create a new DES key object it creates a new instance of the AttributesTemplate class to
   * serve as a template. The application must set all attributes of this new object which are
   * required for the creation of such an object on the token. Then it passes this DESSecretKey
   * object to this method to create the object on the token. Example: <code>
   * AttributesTemplate desKeyTemplate = AttributesTemplate.newSecretKey(CKK_DES3);
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
   * @throws TokenException If the creation of the new object fails. If it fails, the no new object was
   *                        created on the token.
   */
  public long createObject(AttributeVector template) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      return session0.value().createObject(template);
    } finally {
      sessions.requite(session0);
    }
  }

  public long createPrivateKeyObject(AttributeVector template, PublicKey publicKey) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      return session0.value().createPrivateKeyObject(template, publicKey);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Create EC private key object in the PKCS#11 device.
   *
   * @param template Template of the EC private key.
   * @param ecPoint  The encoded EC-Point. May be null.
   * @return object handle of the new EC private key.
   * @throws TokenException if creating new object failed.
   */
  public long createECPrivateKeyObject(AttributeVector template, byte[] ecPoint) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      return session0.value().createECPrivateKeyObject(template, ecPoint);
    } finally {
      sessions.requite(session0);
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
   * @throws TokenException If copying the object fails for some reason.
   */
  public long copyObject(long sourceObjectHandle, AttributeVector template) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      return session0.value().copyObject(sourceObjectHandle, template);
    } finally {
      sessions.requite(session0);
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
   * @param template             This method gets all present attributes of this template object and set this
   *                             attributes at the objectToUpdate.
   * @throws TokenException If updating the attributes fails. All or no attributes are updated.
   */
  public void setAttributeValues(long objectToUpdateHandle, AttributeVector template) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      session0.value().setAttributeValues(objectToUpdateHandle, template);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Destroy a certain object on the token (or in the session). Give the object that you want to
   * destroy. This method uses only the internal object handle of the given object to identify the
   * object.
   *
   * @param objectHandle The object handle that should be destroyed.
   * @throws TokenException If the object could not be destroyed.
   */
  public void destroyObject(long objectHandle) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      session0.value().destroyObject(objectHandle);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Destroy a certain object on the token (or in the session). Give the object that you want to
   * destroy. This method uses only the internal object handle of the given object to identify the
   * object.
   *
   * @param objectHandles The object handles that should be destroyed.
   * @return objects that have been destroyed.
   * @throws TokenException If could not get a valid session.
   */
  public long[] destroyObjects(long... objectHandles) throws TokenException {
    List<Long> list = new ArrayList<>(objectHandles.length);
    for (long handle : objectHandles) {
      list.add(handle);
    }

    List<Long> destroyedHandles = destroyObjects(list);
    long[] ret = new long[destroyedHandles.size()];
    for (int i = 0; i < ret.length; i++) {
      ret[i] = destroyedHandles.get(i);
    }
    return ret;
  }

  public List<Long> destroyObjects(List<Long> objectHandles) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      List<Long> destroyedHandles = new ArrayList<>(objectHandles.size());
      for (long objectHandle : objectHandles) {
        try {
          session.destroyObject(objectHandle);
          destroyedHandles.add(objectHandle);
        } catch (PKCS11Exception e) {
          StaticLogger.warn("error destroying object {}: {}", objectHandle, e.getMessage());
        }
      }

      return destroyedHandles;
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Generate a unique CKA_ID.
   * @param template The search criteria for the uniqueness.
   * @param idLength Length of the CKA_ID.
   * @param random random to generate the random CKA_ID.
   * @return the unique CKA_ID.
   * @throws TokenException If executing operation fails.
   */
  public byte[] generateUniqueId(AttributeVector template, int idLength, Random random) throws TokenException {
    if (template != null && template.id() != null) {
      throw new IllegalArgumentException("template shall not have CKA_ID");
    }

    if (template == null) {
      template = new AttributeVector();
    }

    byte[] keyId = new byte[idLength];
    template.id(keyId);

    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      while (true) {
        random.nextBytes(keyId);
        if (session.findObjectsSingle(template, 1).length == 0) {
          return keyId;
        }
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Gets the {@link PKCS11Key} identified by the given {@link PKCS11KeyId}.
   * @param keyId The key identifier.
   * @return {@link PKCS11Key} identified by the given {@link PKCS11KeyId}.
   * @throws TokenException If executing operation fails.
   */
  public PKCS11Key getKey(PKCS11KeyId keyId) throws TokenException {
    if (keyId == null) {
      return null;
    }

    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return getKey(session, keyId);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Gets the {@link PKCS11Key} of a key satisfying the given criteria.
   * @param criteria The criteria. At one of the CKA_ID and CKA_LABEL must be set.
   * @return {@link PKCS11Key} of a key satisfying the given criteria
   * @throws TokenException If executing operation fails.
   */
  public PKCS11Key getKey(AttributeVector criteria) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      PKCS11KeyId keyId = getKeyId(session, criteria);
      return (keyId == null) ? null : getKey(session, keyId);
    } finally {
      sessions.requite(session0);
    }
  }

  private PKCS11Key getKey(Session session, PKCS11KeyId keyId) throws TokenException {
    long objClass = keyId.getObjectCLass();
    long keyType = keyId.getKeyType();

    List<Long> ckaTypes = new LinkedList<>();

    if (objClass == CKO_SECRET_KEY || objClass == CKO_PRIVATE_KEY) {
      addCkaTypes(ckaTypes, CKA_EXTRACTABLE, CKA_NEVER_EXTRACTABLE, CKA_PRIVATE,
          CKA_DECRYPT, CKA_SIGN, CKA_UNWRAP, CKA_WRAP_WITH_TRUSTED, CKA_SENSITIVE, CKA_ALWAYS_SENSITIVE);

      if (objClass == CKO_SECRET_KEY) {
        addCkaTypes(ckaTypes, CKA_ENCRYPT, CKA_TRUSTED, CKA_VERIFY, CKA_WRAP);

        if (!(keyType == CKK_DES || keyType == CKK_DES2 || keyType == CKK_DES3)) {
          ckaTypes.add(CKA_VALUE_LEN);
        }
      } else {
        addCkaTypes(ckaTypes, CKA_ALWAYS_AUTHENTICATE, CKA_SIGN_RECOVER);

        if (keyType == CKK_RSA) {
          addCkaTypes(ckaTypes, CKA_MODULUS, CKA_PUBLIC_EXPONENT);
        } else if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY
            || keyType == CKK_VENDOR_SM2) {
          ckaTypes.add(CKA_EC_PARAMS);
        } else if (keyType == CKK_DSA) {
          addCkaTypes(ckaTypes, CKA_PRIME, CKA_SUBPRIME, CKA_BASE);
        }
      }
    } else { // if (objClass == CKO_PUBLIC_KEY) {
      addCkaTypes(ckaTypes, CKA_ENCRYPT, CKA_TRUSTED, CKA_VERIFY, CKA_VERIFY_RECOVER, CKA_WRAP);
      if (keyType == CKK_RSA) {
        addCkaTypes(ckaTypes, CKA_MODULUS, CKA_PUBLIC_EXPONENT);
      } else if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY
          || keyType == CKK_VENDOR_SM2) {
        addCkaTypes(ckaTypes, CKA_EC_PARAMS, CKA_EC_POINT);
      } else if (keyType == CKK_DSA) {
        addCkaTypes(ckaTypes, CKA_PRIME, CKA_SUBPRIME, CKA_BASE);
      }
    }

    AttributeVector attrs = session.getAttrValues(keyId.getHandle(), ckaTypes);
    return new PKCS11Key(keyId, attrs);
  }

  /**
   * Gets the {@link PKCS11KeyId} of a key satisfying the given criteria.
   * @param criteria The criteria. At one of the CKA_ID and CKA_LABEL must be set.
   * @return {@link PKCS11KeyId} of a key satisfying the given criteria
   * @throws TokenException If executing operation fails.
   */
  public PKCS11KeyId getKeyId(AttributeVector criteria) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return getKeyId(session, criteria);
    } finally {
      sessions.requite(session0);
    }
  }

  private PKCS11KeyId getKeyId(Session session, AttributeVector criteria) throws TokenException {
    byte[] id = criteria.id();
    String label = criteria.label();
    if ((id == null || id.length == 0) && (label == null || label.isEmpty())) {
      return null;
    }

    Long oClass = criteria.class_();
    if (oClass != null) {
      // CKA_CLASS is set in criteria
      if (!(CKO_PRIVATE_KEY == oClass || CKO_PUBLIC_KEY == oClass || CKO_SECRET_KEY == oClass)) {
        return null;
      }

      long[] handles = session.findObjectsSingle(criteria, 2);
      if (handles.length == 0) {
        return null;
      } else if (handles.length > 1) {
        throw new TokenException("found more than 1 key for the criteria " + criteria);
      } else {
        return getKeyIdByHandle(session, handles[0]);
      }
    }

    // CKA_CLASS is not set in criteria
    oClass = CKO_PRIVATE_KEY;
    long[] handles = session.findObjectsSingle(criteria.class_(oClass), 2);
    if (handles.length == 0) {
      oClass = CKO_SECRET_KEY;
      handles = session.findObjectsSingle(criteria.class_(oClass), 2);

      if (handles.length == 0) {
        oClass = CKO_PUBLIC_KEY;
        handles = session.findObjectsSingle(criteria.class_(oClass), 2);
      }
    }

    if (handles.length == 0) {
      return null;
    } else if (handles.length > 1) {
      throw new TokenException(("found more than 1 key of " + ckoCodeToName(oClass)
          + " for the criteria " + criteria.class_(null)));
    } else {
      return getKeyIdByHandle(session, handles[0]);
    }
  }

  private PKCS11KeyId getKeyIdByHandle(Session session, long hKey) throws TokenException {
    AttributeVector attrs = session.getAttrValues(hKey, CKA_CLASS, CKA_KEY_TYPE, CKA_ID, CKA_LABEL);
    Long oClass = attrs.class_();
    Long keyType = attrs.keyType();
    if (oClass == null || keyType == null) {
      return null;
    }
    byte[] id = attrs.id();
    PKCS11KeyId ret = new PKCS11KeyId(hKey, oClass, keyType, id, attrs.label());
    if (oClass == CKO_PRIVATE_KEY) {
      // find the public key
      long[] pubKeyHandles = session.findObjectsSingle(AttributeVector.newPublicKey(keyType).id(id), 2);
      if (pubKeyHandles.length == 1) {
        ret.setPublicKeyHandle(pubKeyHandles[0]);
      } else if (pubKeyHandles.length > 1) {
        StaticLogger.warn("found more than 1 public key for the private key {}, ignore them.", hKey);
      }
    }
    return ret;
  }

  /**
   * Finds all objects that match the template.
   *
   * @param template The object that serves as a template for searching. If this object is null, the find
   *                 operation will find all objects that this session can see. Notice, that only a user
   *                 session will see private objects.
   * @return An array of found objects. The maximum size of this array is maxObjectCount, the
   * minimum length is 0. Never returns null.
   * @throws TokenException if finding objects failed.
   */
  public long[] findAllObjects(AttributeVector template) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      return session0.value().findAllObjectsSingle(template);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Finds objects that match the template.
   *
   * @param template The object that serves as a template for searching. If this object is null, the find
   *                 operation will find all objects that this session can see. Notice, that only a user
   *                 session will see private objects.
   * @param maxObjectCount Specifies how many objects to return with this call.
   * @return An array of found objects. The maximum size of this array is maxObjectCount, the
   * minimum length is 0. Never returns null.
   * @throws TokenException if finding objects failed.
   */
  public long[] findObjects(AttributeVector template, int maxObjectCount) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      return session0.value().findObjectsSingle(template, maxObjectCount);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Encrypts the given data with the key and mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle The decryption key to use.
   * @param in     buffer containing the to-be-encrypted data
   * @param out    buffer for the encrypted data
   * @return the length of encrypted data
   * @throws PKCS11Exception If encrypting failed.
   */
  public int encrypt(Mechanism mechanism, long keyHandle, byte[] in, byte[] out) throws TokenException {
    return encrypt(mechanism, keyHandle, in, 0, in.length, out, 0, out.length);
  }

  /**
   * Encrypts the given data with the key and mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle The decryption key to use.
   * @param in     buffer containing the to-be-encrypted data
   * @param inOfs  buffer offset of the to-be-encrypted data
   * @param inLen  length of the to-be-encrypted data
   * @param out    buffer for the encrypted data
   * @param outOfs buffer offset for the encrypted data
   * @param outLen buffer size for the encrypted data
   * @return the length of encrypted data
   * @throws PKCS11Exception If encrypting failed.
   */
  public int encrypt(Mechanism mechanism, long keyHandle, byte[] in, int inOfs, int inLen,
                     byte[] out, int outOfs, int outLen) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      opInit(OP.ENCRYPT, session, mechanism, keyHandle);

      if (inLen <= maxMessageSize) {
        return session.encrypt(in, inOfs, inLen, out, outOfs, outLen);
      } else {
        int origOutOfs = outOfs;
        int endInOfs = inOfs + inLen;
        int endOutOfs = outOfs + outLen;

        try {
          for (int ofs = inOfs; ofs < endInOfs; ofs += maxMessageSize) {
            int ciphertextPartLen = session.encryptUpdate(in, ofs, Math.min(maxMessageSize, endInOfs - ofs),
                out, outOfs, endOutOfs - outOfs);
            outOfs += ciphertextPartLen;
          }
        } finally {
          int ciphertextPartLen = session.encryptFinal(out, outOfs, endOutOfs - outOfs);
          outOfs += ciphertextPartLen;
        }

        return outOfs - origOutOfs;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * This method can be used to encrypt large data.
   *
   * @param out        Stream to which the cipher text is written.
   * @param mechanism  The mechanism to use.
   * @param keyHandle  The decryption key to use.
   * @param plaintext  Input-stream of the to-be-encrypted data
   * @return length of the encrypted data.
   * @throws TokenException If encrypting the data failed.
   * @throws IOException if reading data from the plaintext stream failed or writing to the ciphertext stream failed.
   */
  public int encrypt(OutputStream out, Mechanism mechanism, long keyHandle, InputStream plaintext)
      throws TokenException, IOException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      byte[] outBuffer = new byte[maxMessageSize + 256];

      byte[] buffer = new byte[maxMessageSize];
      int read;
      int inSum = 0;
      int outSum = 0;

      // encryptInit
      opInit(OP.ENCRYPT, session, mechanism, keyHandle);

      try {
        while ((read = plaintext.read(buffer)) != -1) {
          int estimatedResLen = maxMessageSize + 32 + (inSum - outSum);
          if (outBuffer.length < estimatedResLen) {
            outBuffer = new byte[estimatedResLen];
          }

          if (read > 0) {
            inSum += read;

            int resLen = session.encryptUpdate(buffer, 0, read, outBuffer, 0, outBuffer.length);
            outSum += resLen;

            if (resLen > 0) {
              out.write(outBuffer, 0, resLen);
            }
          }
        }
      } finally {
        int estimatedResLen = maxMessageSize + 32 + (inSum - outSum);
        if (outBuffer.length < estimatedResLen) {
          outBuffer = new byte[estimatedResLen];
        }

        int resLen = session.encryptFinal(outBuffer, 0, outBuffer.length);
        outSum += resLen;
        if (resLen > 0) {
          out.write(outBuffer, 0, resLen);
        }
      }

      return outSum;
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Decrypts the given data with the key and mechanism.
   *
   * @param mechanism  The mechanism to use.
   * @param keyHandle  The decryption key to use.
   * @param in     buffer containing the to-be-decrypted data
   * @param out    buffer for the decrypted data
   * @return the length of decrypted data
   * @throws PKCS11Exception If decrypting failed.
   */
  public int decrypt(Mechanism mechanism, long keyHandle, byte[] in, byte[] out) throws TokenException {
    return decrypt(mechanism, keyHandle, in, 0, in.length, out, 0, out.length);
  }

  /**
   * Decrypts the given data with the key and mechanism.
   *
   * @param mechanism  The mechanism to use.
   * @param keyHandle  The decryption key to use.
   * @param in     buffer containing the to-be-decrypted data
   * @param inOfs  buffer offset of the to-be-decrypted data
   * @param inLen  length of the to-be-decrypted data
   * @param out    buffer for the decrypted data
   * @param outOfs buffer offset for the decrypted data
   * @param outLen buffer size for the decrypted data
   * @return the length of decrypted data
   * @throws PKCS11Exception If decrypting failed.
      */
  public int decrypt(Mechanism mechanism, long keyHandle, byte[] in, int inOfs, int inLen,
                     byte[] out, int outOfs, int outLen) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();

    try {
      opInit(OP.DECRYPT, session, mechanism, keyHandle);
      return session.decrypt(in, inOfs, inLen, out, outOfs, outLen);
    /* BUGs in the underlying PKCS11 of JDK.
      if (inLen <= maxMessageSize) {
        return session.decryptSingle(mechanism, keyHandle, in, inOfs, inLen, out, outOfs, outLen);
      } else {
        int origOutOfs = outOfs;
        int endInOfs = inOfs + inLen;
        int endOutOfs = outOfs + outLen;

        session.decryptInit(mechanism, keyHandle);

        try {
          for (int ofs = inOfs; ofs < endInOfs; ofs += maxMessageSize) {
            int plaintextPartLen = session.decryptUpdate(in, inOfs, Math.min(maxMessageSize, endInOfs- ofs),
                out, outOfs, endOutOfs - outOfs);
            outOfs += plaintextPartLen;
          }
        } finally {
          int plaintextPartLen = session.decryptFinal(out, outOfs, endOutOfs - outOfs);
          outOfs += plaintextPartLen;
        }
        return outOfs - origOutOfs;
      }
      */
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * This method can be used to decrypt large data.
   *
   * @param out        Stream to which the plain text is written.
   * @param mechanism  The mechanism to use.
   * @param keyHandle  The decryption key to use.
   * @param ciphertext Input-stream of the to-be-encrypted data
   * @return length of the decrypted data.
   * @throws TokenException If decrypting the data failed.
   * @throws IOException if reading data from the ciphertext stream failed or writing to the plaintext stream failed.
   */
  public int decrypt(OutputStream out, Mechanism mechanism, long keyHandle, InputStream ciphertext)
      throws TokenException, IOException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      byte[] ciphertextBytes = readAllBytes(ciphertext);
      byte[] plaintextBytes = new byte[ciphertextBytes.length];
      opInit(OP.DECRYPT, session, mechanism, keyHandle);
      int plaintextLen = session.decrypt(ciphertextBytes, plaintextBytes);
      out.write(plaintextBytes, 0, plaintextLen);
      return plaintextLen;

      /* BUGs in the PKCS11 of JDK
      byte[] outBuffer = new byte[maxMessageSize + 256];

      byte[] buffer = new byte[maxMessageSize];
      int read;
      int inSum = 0;
      int outSum = 0;

      // decryptInit
      session.decryptInit(mechanism, keyHandle);

      try {
        while ((read = ciphertext.read(buffer)) != -1) {
          if (read > 0) {
            inSum += read;

            int resLen = session.decryptUpdate(buffer, 0, read, outBuffer, 0, outBuffer.length);
            outSum += resLen;

            if (resLen > 0) {
              out.write(outBuffer, 0, resLen);
            }
          }
        }
      } finally {
        int estimatedResLen = maxMessageSize + 32 + (inSum - outSum);
        if (outBuffer.length < estimatedResLen) {
          outBuffer = new byte[estimatedResLen];
        }

        int resLen = session.decryptFinal(outBuffer, 0, outBuffer.length);
        outSum += resLen;
        if (resLen > 0) {
          out.write(outBuffer, 0, resLen);
        }
      }

      return outSum;
       */
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Digests the given data with the mechanism.
   *
   * @param mechanism The mechanism to use.
   * @param in   the to-be-digested data
   * @return the length of digested data for this update
   * @throws PKCS11Exception If digesting the data failed.
   */
  public byte[] digest(Mechanism mechanism, byte[] in) throws TokenException {
    return digest(mechanism, in, 0, in.length);
  }

  /**
   * Digests the given data with the mechanism.
   *
   * @param mechanism The mechanism to use.
   * @param in     buffer containing the to-be-digested data
   * @param inOfs  buffer offset of the to-be-digested data
   * @param inLen  length of the to-be-digested data
   * @return the length of digested data for this update
   * @throws PKCS11Exception If digesting the data failed.
   */
  public byte[] digest(Mechanism mechanism, byte[] in, int inOfs, int inLen) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      int digestLen = estimateDigestLen(mechanism);
      byte[] digest = new byte[digestLen];
      int outLen;

      opInit(OP.DIGEST, session, mechanism, 0);

      if (inLen < maxMessageSize) {
        outLen = session.digest(in, inOfs, inLen, digest, 0, digestLen);
      } else {
        try {
          int endInOfs = inOfs + inLen;
          for (int ofs = inOfs; ofs < endInOfs; ofs += maxMessageSize) {
            session.signUpdate(in, ofs, Math.min(maxMessageSize, endInOfs - ofs));
          }
        } finally {
          outLen = session.digestFinal(digest, 0, digestLen);
        }
      }
      return (outLen == digestLen) ? digest : Arrays.copyOf(digest, outLen);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Digests the given key with the mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.SHA_1.
   * @param keyHandle handle of the to-be-digested key.
   * @return the message digest. Never returns {@code null}.
   * @throws TokenException If digesting the data failed.
   */
  public byte[] digestKey(Mechanism mechanism, long keyHandle) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      opInit(OP.DIGEST, session, mechanism, 0);
      byte[] digest;
      try {
        session.digestKey(keyHandle);
      } finally {
        int digestLen = estimateDigestLen(mechanism);
        digest = new byte[digestLen];
        int len = session.digestFinal(digest, 0, digest.length);
        if (len != digestLen) {
          digest = Arrays.copyOf(digest, len);
        }
      }
      return digest;
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Digests the large data with the mechanism.
   *
   * @param mechanism  The mechanism to use; e.g. Mechanism.SHA_1.
   * @param data       the to-be-digested data
   * @return the message digest. Never returns {@code null}.
   * @throws TokenException If digesting the data failed.
   * @throws IOException if reading data from stream failed.
   */
  public byte[] digest(Mechanism mechanism, InputStream data) throws TokenException, IOException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      byte[] buffer = new byte[maxMessageSize];
      int read;

      int digestLen = estimateDigestLen(mechanism);
      byte[] digest = new byte[digestLen];

      opInit(OP.DIGEST, session, mechanism, 0);

      int outLen;
      try {
        while ((read = data.read(buffer)) != -1) {
          if (read > 0) {
            session.digestUpdate(copyOfLen(buffer, read));
          }
        }
      } finally {
        outLen = session.digestFinal(digest, 0, digestLen);
      }
      return (outLen == digestLen) ? digest : Arrays.copyOf(digest, outLen);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Signs the given data with the key and mechanism.
   *
   * @param mechanism The mechanism to use.
   * @param keyHandle The signing key to use.
   * @param in        The data to sign.
   * @return The signed data. Never returns {@code null}.
   * @throws TokenException If signing the data failed.
   */
  public byte[] sign(Mechanism mechanism, long keyHandle, byte[] in) throws TokenException {
    return sign(mechanism, keyHandle, in, 0, in.length);
  }

  /**
   * Signs the given data with the key and mechanism.
   *
   * @param mechanism The mechanism to use.
   * @param keyHandle The signing key to use.
   * @param in        The data to sign.
   * @param inOfs     buffer offset of the to-be-signed data
   * @param inLen     length of the to-be-signed data
   * @return The signed data. Never returns {@code null}.
   * @throws TokenException If signing the data failed.
   */
  public byte[] sign(Mechanism mechanism, long keyHandle, byte[] in, int inOfs, int inLen) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      opInit(OP.SIGN, session, mechanism, keyHandle);
      if (inLen < maxMessageSize) {
        return session.sign(copyOfLen(in, inOfs, inLen));
      } else {
        try {
          byte[] signature;
          int endInOfs = inOfs + inLen;
          try {
            for (int ofs = inOfs; ofs < endInOfs; ofs += maxMessageSize) {
              session.signUpdate(in, ofs, Math.min(maxMessageSize, endInOfs - ofs));
            }
          } finally {
            signature = session.signFinal();
          }
          return signature;
        } catch (PKCS11Exception e) {
          if (e.getErrorCode() == CKR_OPERATION_NOT_INITIALIZED) {
            opInit(OP.SIGN, session, mechanism, keyHandle);
            return session.sign(copyOfLen(in, inOfs, inLen));
          } else {
            throw e;
          }
        }
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * This method can be used to sign large data.
   *
   * @param mechanism  The mechanism to use.
   * @param keyHandle  The signing key to use.
   * @param data       Input-stream of the to-be-signed data
   * @return length of the signature.
   * @throws TokenException If signing the data failed.
   * @throws IOException If reading data stream failed.
   */
  public byte[] sign(Mechanism mechanism, long keyHandle, InputStream data)
      throws TokenException, IOException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      byte[] buffer = new byte[maxMessageSize];
      int firstBlockLen = readBytes(data, buffer, maxMessageSize);
      byte[] firstBlock = copyOfLen(buffer, firstBlockLen);
      opInit(OP.SIGN, session, mechanism, keyHandle);

      if (firstBlockLen < maxMessageSize) {
        return session.sign(firstBlock);
      } else {
        int read;
        try {
          session.signUpdate(firstBlock);
        } catch (PKCS11Exception e) {
          if (e.getErrorCode() == CKR_OPERATION_NOT_INITIALIZED) {
            ByteArrayOutputStream bout = new ByteArrayOutputStream(maxMessageSize + data.available());
            bout.write(firstBlock);

            while ((read = data.read(buffer)) != -1) {
              bout.write(buffer, 0, read);
            }
            opInit(OP.SIGN, session, mechanism, keyHandle);
            return session.sign(bout.toByteArray());
          }
        }

        byte[] signature;
        try {
          while ((read = data.read(buffer)) != -1) {
            if (read > 0) {
              session.signUpdate(copyOfLen(buffer, read));
            }
          }
        } finally {
          signature = session.signFinal();
        }

        return signature;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Sign-recovers the given data with the key and mechanism.
   *
   * @param mechanism The mechanism to use.
   * @param keyHandle The signing key to use.
   * @param in     buffer containing the to-be-signed data
   * @param out    buffer for the signed data
   * @return the length of signed data
   * @throws PKCS11Exception If signing the data failed.
   */
  public int signRecover(Mechanism mechanism, long keyHandle, byte[] in, byte[] out) throws TokenException {
    return signRecover(mechanism, keyHandle, in, 0, in.length, out, 0, out.length);
  }

  /**
   * Sign-recovers the given data with the key and mechanism.
   *
   * @param mechanism The mechanism to use.
   * @param keyHandle The signing key to use.
   * @param in     buffer containing the to-be-signed data
   * @param inOfs  buffer offset of the to-be-signed data
   * @param inLen  length of the to-be-signed data
   * @param out    buffer for the signed data
   * @param outOfs buffer offset for the signed data
   * @param outLen buffer size for the signed data
   * @return the length of signed data
   * @throws PKCS11Exception If signing the data failed.
   */
  public int signRecover(Mechanism mechanism, long keyHandle, byte[] in, int inOfs, int inLen,
                         byte[] out, int outOfs, int outLen) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      Session session = session0.value();
      opInit(OP.SIGN_RECOVER, session, mechanism, keyHandle);
      return session.signRecover(in, inOfs, inLen, out, outOfs, outLen);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Verifies the given signature against the given data with the key and mechanism.
   * This method throws an exception, if the verification of the signature fails.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param keyHandle The verification key to use.
   * @param data      The data that was signed.
   * @param signature The signature or MAC to verify.
   * @return true if signature is invalid, false otherwise.
   * @throws TokenException If verifying the signature fails.
   */
  public boolean verify(Mechanism mechanism, long keyHandle, byte[] data, byte[] signature) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    int len = data.length;

    long code = mechanism.getMechanismCode();
    try {
      if (supportsMechanism(code, CKF_VERIFY)) {
        try {
          opInit(OP.VERIFY, session, mechanism, keyHandle);

          if (len <= maxMessageSize) {
            session.verify(data, signature);
          } else {
            try {
              try {
                for (int ofs = 0; ofs < len; ofs += maxMessageSize) {
                  session.verifyUpdate(copyOfLen(data, ofs, Math.min(maxMessageSize, len - ofs)));
                }
              } finally {
                session.verifyFinal(signature);
              }
            } catch (PKCS11Exception e) {
              if (e.getErrorCode() == CKR_OPERATION_NOT_INITIALIZED) {
                opInit(OP.VERIFY, session, mechanism, keyHandle);
                session.verify(data, signature);
              } else {
                throw e;
              }
            }
          }
          return true;
        } catch (PKCS11Exception e) {
          long ckr = e.getErrorCode();
          if (ckr == CKR_SIGNATURE_INVALID || ckr == CKR_SIGNATURE_LEN_RANGE) {
            return false;
          } else {
            throw e;
          }
        }
      } else if (supportsMechanism(code, CKF_SIGN) && isMacMechanism(code)) {
        // CKF_VERIFY is not supported, use CKF_SIGN to verify the MAC tags.
        opInit(OP.SIGN, session, mechanism, keyHandle);
        byte[] sig2;
        if (len <= maxMessageSize) {
          sig2 = session.sign(data);
        } else {
          try {
            for (int ofs = 0; ofs < len; ofs += maxMessageSize) {
              session.signUpdate(copyOfLen(data, ofs, Math.min(maxMessageSize, len - ofs)));
            }
          } finally {
            sig2 = session.signFinal();
          }
        }
        return Arrays.equals(signature, sig2);
      } else {
        throw new PKCS11Exception(CKR_MECHANISM_INVALID);
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * This method can be used to verify large data.
   *
   * @param mechanism  The mechanism to use.
   * @param keyHandle  The signing key to use.
   * @param data       Input-stream of the to-be-verified data
   * @param signature  the signature.
   * @return true if signature is invalid, false otherwise.
   * @throws TokenException If signing the data failed.
   * @throws IOException If reading data stream failed.
   */
  public boolean verify(Mechanism mechanism, long keyHandle, InputStream data, byte[] signature)
      throws TokenException, IOException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      byte[] buffer = new byte[maxMessageSize];
      int firstBlockLen = readBytes(data, buffer, maxMessageSize);
      byte[] firstBlock = copyOfLen(buffer, firstBlockLen);

      long code = mechanism.getMechanismCode();
      if (supportsMechanism(code, CKF_VERIFY)) {
        opInit(OP.VERIFY, session, mechanism, keyHandle);
        if (firstBlockLen < maxMessageSize) {
          session.verify(firstBlock, signature);
          return true;
        } else {
          try {
            session.verifyUpdate(firstBlock);
          } catch (PKCS11Exception e) {
            if (e.getErrorCode() == CKR_OPERATION_NOT_INITIALIZED) {
              ByteArrayOutputStream bout = new ByteArrayOutputStream(maxMessageSize + data.available());
              bout.write(firstBlock);

              int read;
              while ((read = data.read(buffer)) != -1) {
                bout.write(buffer, 0, read);
              }
              opInit(OP.VERIFY, session, mechanism, keyHandle);
              session.verify(bout.toByteArray(), signature);
              return true;
            }
          }

          try {
            int read;
            while ((read = data.read(buffer)) != -1) {
              if (read > 0) {
                session.verifyUpdate(copyOfLen(buffer, read));
              }
            }
          } finally {
            session.verifyFinal(signature);
          }

          return true;
        }
      } else if (supportsMechanism(code, CKF_SIGN) && isMacMechanism(code)) {
        byte[] sig2;
        opInit(OP.SIGN, session, mechanism, keyHandle);

        if (firstBlockLen < maxMessageSize) {
          sig2 = session.sign(firstBlock);
        } else {
          try {
            session.signUpdate(firstBlock);
            int read;
            while ((read = data.read(buffer)) != -1) {
              if (read > 0) {
                session.signUpdate(buffer, 0, read);
              }
            }
          } finally {
            sig2 = session.signFinal();
          }
        }
        return Arrays.equals(signature, sig2);
      } else {
        throw new PKCS11Exception(CKR_MECHANISM_INVALID);
      }
    } catch (PKCS11Exception e) {
      long ckr = e.getErrorCode();
      if (ckr == CKR_SIGNATURE_INVALID || ckr == CKR_SIGNATURE_LEN_RANGE) {
        return false;
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Verifies the given data with the key and mechanism.
   *
   * @param mechanism The mechanism to use.
   * @param keyHandle The verification key to use.
   * @param in buffer containing the to-be-verified data
   * @param out buffer for the verified data
   * @return the length of verified data
   * @exception PKCS11Exception
   *              If signing the data failed.
   */
  public int verifyRecover(Mechanism mechanism, long keyHandle, byte[] in, byte[] out) throws TokenException {
    return verifyRecover(mechanism, keyHandle, in, 0, in.length, out, 0, out.length);
  }

  /**
   * Verifies the given data with the key and mechanism.
   *
   * @param mechanism The mechanism to use.
   * @param keyHandle The verification key to use.
   * @param in buffer containing the to-be-verified data
   * @param inOfs buffer offset of the to-be-verified data
   * @param inLen length of the to-be-verified data
   * @param out buffer for the verified data
   * @param outOfs buffer offset for the verified data
   * @param outLen buffer size for the verified data
   * @return the length of verified data
   * @exception PKCS11Exception
   *              If signing the data failed.
   */
  public int verifyRecover(Mechanism mechanism, long keyHandle, byte[] in, int inOfs, int inLen,
                           byte[] out, int outOfs, int outLen) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      Session session = session0.value();
      opInit(OP.VERIFY_RECOVER, session, mechanism, keyHandle);
      return session.verifyRecover(in, inOfs, inLen, out, outOfs, outLen);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Generate a new secret key or a set of domain parameters. It uses the set attributes of the
   * template for setting the attributes of the new key object. As mechanism the application can use
   * a constant of the Mechanism class.
   *
   * @param mechanism The mechanism to generate a key for; e.g. Mechanism.DES to generate a DES key.
   * @param template  The template for the new key or domain parameters; e.g. a DESSecretKey object which
   *                  has set certain attributes.
   * @return The newly generated secret key or domain parameters.
   * @throws TokenException If generating a new secret key or domain parameters failed.
   */
  public long generateKey(Mechanism mechanism, AttributeVector template) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      return session0.value().generateKey(mechanism, template);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Generate a new public key - private key key-pair and use the set attributes of the template
   * objects for setting the attributes of the new public key and private key objects. As mechanism
   * the application can use a constant of the Mechanism class.
   *
   * @param mechanism The mechanism to generate a key for; e.g. Mechanism.RSA to generate a new RSA
   *                  key-pair.
   * @param template  The template for the new keypair.
   * @return The newly generated key-pair.
   * @throws TokenException If generating a new key-pair failed.
   */
  public PKCS11KeyPair generateKeyPair(Mechanism mechanism, KeyPairTemplate template) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      return session0.value().generateKeyPair(mechanism, template);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Wraps (encrypts) the given key with the wrapping key using the given mechanism.
   *
   * @param mechanism         The mechanism to use for wrapping the key.
   * @param wrappingKeyHandle The key to use for wrapping (encrypting).
   * @param keyHandle         The key to wrap (encrypt).
   * @return The wrapped key as byte array. Never returns {@code null}.
   * @throws TokenException If wrapping the key failed.
   */
  public byte[] wrapKey(Mechanism mechanism, long wrappingKeyHandle, long keyHandle) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      return session0.value().wrapKey(mechanism, wrappingKeyHandle, keyHandle);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Unwraps (decrypts) the given encrypted key with the unwrapping key using the given mechanism.
   * The application can also pass a template key to set certain attributes of the unwrapped key.
   * This creates a key object after unwrapping the key and returns an object representing this key.
   *
   * @param mechanism           The mechanism to use for unwrapping the key.
   * @param unwrappingKeyHandle The key to use for unwrapping (decrypting).
   * @param wrappedKey          The encrypted key to unwrap (decrypt).
   * @param keyTemplate         The template for creating the new key object.
   * @return A key object representing the newly created key object.
   * @throws TokenException If unwrapping the key or creating a new key object failed.
   */
  public long unwrapKey(Mechanism mechanism, long unwrappingKeyHandle, byte[] wrappedKey,
                        AttributeVector keyTemplate) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      return session0.value().unwrapKey(mechanism, unwrappingKeyHandle, wrappedKey, keyTemplate);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Derives a new key from a specified base key using the given mechanism. After deriving a new
   * key from the base key, a new key object is created and a representation of it is returned. The
   * application can provide a template key to set certain attributes of the new key object.
   *
   * @param mechanism     The mechanism to use for deriving the new key from the base key.
   * @param baseKeyHandle The key to use as base for derivation.
   * @param template      The template for creating the new key object.
   * @return A key object representing the newly derived (created) key object or null, if the used
   * mechanism uses other means to return its values; e.g. the CKM_SSL3_KEY_AND_MAC_DERIVE
   * mechanism.
   * @throws TokenException If deriving the key or creating a new key object failed.
   */
  public long deriveKey(Mechanism mechanism, long baseKeyHandle, AttributeVector template) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      return session0.value().deriveKey(mechanism, baseKeyHandle, template);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Generates a certain number of random bytes.
   *
   * @param numberOfBytesToGenerate The number of random bytes to generate.
   * @return An array of random bytes with length numberOfBytesToGenerate.
   * @throws TokenException If generating random bytes failed.
   */
  public byte[] generateRandom(int numberOfBytesToGenerate) throws TokenException {
    return generateRandom(numberOfBytesToGenerate, null);
  }

  /**
   * Generates a certain number of random bytes.
   *
   * @param numberOfBytesToGenerate The number of random bytes to generate.
   * @param extraSeed               The seed bytes to mix in.
   * @return An array of random bytes with length numberOfBytesToGenerate.
   * @throws TokenException If generating random bytes failed.
   */
  public byte[] generateRandom(int numberOfBytesToGenerate, byte[] extraSeed) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      if (extraSeed != null && extraSeed.length > 0) {
        session.seedRandom(extraSeed);
      }
      return session.generateRandom(numberOfBytesToGenerate);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return "User type: " + codeToName(Category.CKU, userType) +
        "\nMaximal session count: " + maxSessionCount +
        "\nNew session timeout: " + timeOutWaitNewSessionMs + " ms" +
        "\nRead only: " + readOnly +
        "\nToken: " + token;
  }

  /**
   * Gets give attributes for the given object handle.
   * @param objectHandle the object handle.
   * @param attributeTypes types of attributes to be read.
   * @return attributes for the given object handle.
   * @throws TokenException if getting attributes failed.
   */
  public AttributeVector getAttrValues(long objectHandle, long... attributeTypes) throws TokenException {
    List<Long> typeList = new ArrayList<>(attributeTypes.length);
    for (long attrType : attributeTypes) {
      typeList.add(attrType);
    }
    return getAttrValues(objectHandle, typeList);
  }

  /**
   * Gets give attributes for the given object handle.
   * @param objectHandle the object handle.
   * @param attributeTypes types of attributes to be read.
   * @return attributes for the given object handle.
   * @throws TokenException if getting attributes failed.
   */
  public AttributeVector getAttrValues(long objectHandle, List<Long> attributeTypes) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      return session0.value().getAttrValues(objectHandle, attributeTypes);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Gets all attributes for the given object handle.
   * @param objectHandle the object handle.
   * @return all attributes for the given object handle.
   * @throws TokenException if getting attributes failed.
   */
  public AttributeVector getDefaultAttrValues(long objectHandle) throws TokenException {
    BagEntry<Session> session0 = borrowSession();
    try {
      return session0.value().getDefaultAttrValues(objectHandle);
    } finally {
      sessions.requite(session0);
    }
  }

  private Session openSession() throws PKCS11Exception {
    Session session = token.openSession(!readOnly);
    countSessions.incrementAndGet();
    return session;
  }

  private BagEntry<Session> borrowSession() throws TokenException {
    return borrowSession(true);
  }

  private BagEntry<Session> borrowNoLoginSession() throws TokenException {
    return borrowSession(false);
  }

  private BagEntry<Session> borrowSession(boolean login) throws TokenException {
    long maxTimeMs = clock.millis() + timeOutWaitNewSessionMs;
    int maxTries = maxSessionCount + 1;
    for (int retries = 0; retries < maxTries; retries++) {
      BagEntry<Session> sessionBagEntry = borrowSession(login, maxTimeMs);
      if (sessionBagEntry != null) {
        if (retries != 0) {
          StaticLogger.info("Borrowed session after " + (retries + 1) + " tries.");
        }
        return sessionBagEntry;
      }
    }

    throw new TokenException("could not borrow session after " + maxTries + " tries.");
  }
  private BagEntry<Session> borrowSession(boolean login, long maxTimeMs) throws TokenException {
    if (maxTimeMs == 0) {
      maxTimeMs = clock.millis() + timeOutWaitNewSessionMs;
    }

    BagEntry<Session> session = null;
    synchronized (sessions) {
      if (countSessions.get() < maxSessionCount) {
        try {
          session = sessions.borrow(1, TimeUnit.NANOSECONDS);
        } catch (InterruptedException ex) {
        }

        if (session == null) {
          // create new session
          sessions.add(new BagEntry<>(openSession()));
        }
      }
    }

    if (session == null) {
      long timeOutMs = maxTimeMs - clock.millis();
      try {
        session = sessions.borrow(Math.max(1, timeOutMs), TimeUnit.MILLISECONDS);
      } catch (InterruptedException ex) {
      }
    }

    if (session == null) {
      throw new TokenException("no idle session");
    }

    boolean requiteSession = true;

    try {
      boolean sessionActive = true;
      SessionInfo sessionInfo = null;
      try {
        sessionInfo = session.value().getSessionInfo();
      } catch (PKCS11Exception ex) {
        long ckr = ex.getErrorCode();
        if (ckr == CKR_SESSION_CLOSED || ckr == CKR_SESSION_HANDLE_INVALID) {
          sessionActive = false;
        }
        StaticLogger.warn("error getSessionInfo: {}", ckrCodeToName(ckr));
      }

      if (sessionActive && sessionInfo != null) {
        long deviceError = sessionInfo.getDeviceError();
        if (deviceError != 0) {
          if (getModule().hasVendorBehaviour(PKCS11Module.BEHAVIOUR_IGNORE_DEVICE_ERROR)) {
            StaticLogger.warn("ignore device error {}", deviceError);
          } else {
            sessionActive = false;
            StaticLogger.error("device has error {}", deviceError);
          }
        }
      }

      if (!sessionActive) {
        requiteSession = false;
        sessions.remove(session);
        countSessions.decrementAndGet();
        return null;
      }

      if (login) {
        boolean loggedIn = false;
        if (sessionInfo != null) {
          long state = sessionInfo.getState();
          loggedIn = (state == CKS_RW_SO_FUNCTIONS)
                      || (state == CKS_RW_USER_FUNCTIONS) || (state == CKS_RO_USER_FUNCTIONS);
        }

        if (!loggedIn) {
          synchronized (loginSync) {
            try {
              sessionInfo = session.value().getSessionInfo();
              loggedIn = isSessionLoggedIn(sessionInfo);
            } catch (Exception e) {
              StaticLogger.debug("Error while getSessionInfo()", e);
            }

            if (!loggedIn) {
              login(session.value());
            }
          }
        }
      }

      requiteSession = false;
      return session;
    } finally {
      if (requiteSession) {
        sessions.requite(session);
      }
    }
  } // method borrowSession

  private static boolean isSessionLoggedIn(SessionInfo sessionInfo) {
    long state = sessionInfo.getState();
    return  (state == CKS_RW_SO_FUNCTIONS)
        || (state == CKS_RW_USER_FUNCTIONS) || (state == CKS_RO_USER_FUNCTIONS);
  }

  private void login(Session session) throws TokenException {
    login(session, userType, pins);
  }

  private void login(Session session, long userType, List<char[]> pins) throws TokenException {
    synchronized (loginSync) {
      StaticLogger.info("verify on PKCS11Module with " + (pins == null || pins.isEmpty() ? "NULL pin" : "pin"));

      String userText = "user of type " + codeToName(Category.CKU, userType);
      boolean nullPins;
      if (pins == null || pins.isEmpty()) {
        nullPins = true;
      } else if (pins.size() == 1) {
        char[] pin = pins.get(0);
        nullPins = pin == null || pin.length == 0;
      } else {
        nullPins = false;
      }

      try {
        if (nullPins) {
          session.login(userType, new char[0]);
          StaticLogger.info("login successful as " + userText + " with NULL PIN");
        } else {
          for (char[] pin : pins) {
            session.login(userType, pin == null ? new char[0] : pin);
          }
          StaticLogger.info("login successful as " + userText + " with PIN");
        }
      } catch (PKCS11Exception ex) {
        long ckr = ex.getErrorCode();
        if (ckr == CKR_USER_ALREADY_LOGGED_IN) {
          StaticLogger.info("user already logged in");
        } else {
          StaticLogger.warn("login failed as {}: {}", userText, ckrCodeToName(ckr));
          throw ex;
        }
      }
    }
  }

  private void opInit(OP op, Session session, Mechanism mechanism, long keyHandle) throws TokenException {
    try {
      opInit0(op, session, mechanism, keyHandle);
    } catch (PKCS11Exception ex) {
      if (ex.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        opInit0(op, session, mechanism, keyHandle);
      }
    }
  }

  private void opInit0(OP op, Session session, Mechanism mechanism, long keyHandle) throws TokenException {
    switch (op) {
      case SIGN:
        session.signInit(mechanism, keyHandle);
        break;
      case VERIFY:
        session.verifyInit(mechanism, keyHandle);
        break;
      case DECRYPT:
        session.decryptInit(mechanism, keyHandle);
        break;
      case ENCRYPT:
        session.encryptInit(mechanism, keyHandle);
        break;
      case DIGEST:
        session.digestInit(mechanism);
        break;
      case SIGN_RECOVER:
        session.signRecoverInit(mechanism, keyHandle);
        break;
      case VERIFY_RECOVER:
        session.verifyRecoverInit(mechanism, keyHandle);
        break;
      default:
        throw new IllegalStateException("unknown OP " + op);
    }
  }

  private static byte[] copyOfLen(byte[] bytes, int len) {
    return bytes.length == len ? bytes : Arrays.copyOf(bytes, len);
  }

  private static byte[] copyOfLen(byte[] bytes, int offset, int len) {
    return (offset == 0 && bytes.length == len) ? bytes : Arrays.copyOfRange(bytes, offset, offset + len);
  }

  private static int estimateDigestLen(Mechanism mechanism) {
    long mechCode = mechanism.getMechanismCode();
    int digestLen;
    if (mechCode == CKM_SHA_1) {
      digestLen = 20;
    } else if (mechCode == CKM_SHA224 || mechCode == CKM_SHA3_224) {
      digestLen = 28;
    } else if (mechCode == CKM_SHA256 || mechCode == CKM_SHA3_256 || mechCode == CKM_VENDOR_SM3) {
      digestLen = 32;
    } else if (mechCode == CKM_SHA384 || mechCode == CKM_SHA3_384) {
      digestLen = 48;
    } else if (mechCode == CKM_SHA512 || mechCode == CKM_SHA3_512) {
      digestLen = 64;
    } else {
      digestLen = 64;
    }
    return digestLen;
  }

  private static byte[] readAllBytes(InputStream stream) throws IOException {
    ByteArrayOutputStream bout = new ByteArrayOutputStream(Math.min(32, stream.available()));
    int read;
    byte[] buffer = new byte[4096];
    while ((read = stream.read(buffer)) != -1) {
      bout.write(buffer, 0, read);
    }
    return bout.toByteArray();
  }

  private static int readBytes(InputStream stream, byte[] buffer, int numBytes) throws IOException {
    int ofs = 0;
    int read;
    while ((read = stream.read(buffer, ofs, numBytes - ofs)) != -1) {
      ofs += read;
      if (ofs >= numBytes) {
        break;
      }
    }
    return ofs;
  }

  private static boolean isMacMechanism(long mechanism) {
    return mechanism == CKM_AES_CMAC || mechanism == CKM_AES_GMAC || mechanism == CKM_SHA_1_HMAC ||
        mechanism == CKM_SHA224_HMAC || mechanism == CKM_SHA256_HMAC ||
        mechanism == CKM_SHA384_HMAC || mechanism == CKM_SHA512_HMAC ||
        mechanism == CKM_SHA3_224_HMAC || mechanism == CKM_SHA3_256_HMAC ||
        mechanism == CKM_SHA3_384_HMAC || mechanism == CKM_SHA3_512_HMAC ||
        mechanism == CKM_SHA224_HMAC_GENERAL || mechanism == CKM_SHA256_HMAC_GENERAL ||
        mechanism == CKM_SHA384_HMAC_GENERAL || mechanism == CKM_SHA512_HMAC_GENERAL ||
        mechanism == CKM_SHA3_224_HMAC_GENERAL || mechanism == CKM_SHA3_256_HMAC_GENERAL ||
        mechanism == CKM_SHA3_384_HMAC_GENERAL || mechanism == CKM_SHA3_512_HMAC_GENERAL;
  }

  private static void addCkaTypes(List<Long> list, long... types) {
    for (long type : types) {
      list.add(type);
    }
  }

}
