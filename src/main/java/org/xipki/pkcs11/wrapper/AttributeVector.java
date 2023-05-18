// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.xipki.pkcs11.wrapper.attrs.*;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;

import java.math.BigInteger;
import java.time.Instant;
import java.util.*;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Object of this class represents the attribute vector.
 *
 * @author Lijun Liao (xipki)
 */
public class AttributeVector {

  private final List<Attribute> attributes = new LinkedList<>();

  public AttributeVector() {
  }

  public AttributeVector(Attribute... attributes) {
    if (attributes != null) {
      for (Attribute attr : attributes) {
        if (attr != null) {
          attr(attr);
        }
      }
    }
  }

  public static AttributeVector newSecretKey() {
    return new AttributeVector().class_(CKO_SECRET_KEY);
  }

  public static AttributeVector newSecretKey(long keyType) {
    return newSecretKey().keyType(keyType);
  }

  public static AttributeVector newAESSecretKey() {
    return newSecretKey(CKK_AES);
  }

  public static AttributeVector newPrivateKey() {
    return new AttributeVector().class_(CKO_PRIVATE_KEY);
  }

  public static AttributeVector newPrivateKey(long keyType) {
    return newPrivateKey().keyType(keyType);
  }

  public static AttributeVector newRSAPrivateKey() {
    return newPrivateKey(CKK_RSA);
  }

  public static AttributeVector newECPrivateKey() {
    return newPrivateKey(CKK_EC);
  }

  public static AttributeVector newDSAPrivateKey() {
    return newPrivateKey(CKK_DSA);
  }

  public static AttributeVector newPublicKey() {
    return new AttributeVector().class_(CKO_PUBLIC_KEY);
  }

  public static AttributeVector newPublicKey(long keyType) {
    return newPublicKey().keyType(keyType);
  }

  public static AttributeVector newRSAPublicKey() {
    return newPublicKey(CKK_RSA);
  }

  public static AttributeVector newECPublicKey() {
    return newPublicKey(CKK_EC);
  }

  public static AttributeVector newDSAPublicKey() {
    return newPublicKey(CKK_DSA);
  }

  public static AttributeVector newCertificate(long certificateType) {
    return new AttributeVector().class_(CKO_CERTIFICATE).certificateType(certificateType);
  }

  public static AttributeVector newX509Certificate() {
    return newCertificate(CKC_X_509);
  }

  public AttributeVector attr(long attrType, Object attrValue) {
    return attr(Attribute.getInstance(attrType, attrValue));
  }

  public AttributeVector attr(Attribute attr) {
    if (!attributes.isEmpty()) {
      long type = attr.getType();
      int oldAttrIdx = -1;
      for (int i = 0; i < attributes.size(); i++) {
        if (attributes.get(i).getType() == type) {
          oldAttrIdx = i;
          break;
        }
      }

      if (oldAttrIdx != -1) {
        attributes.remove(oldAttrIdx);
      }
    }

    attributes.add(attr);
    return this;
  }

  public List<Attribute> snapshot() {
    return Collections.unmodifiableList(attributes);
  }

  public CK_ATTRIBUTE[] toCkAttributes() {
    List<CK_ATTRIBUTE> attributeList = new ArrayList<>();
    for (Attribute attribute : attributes) {
      if (attribute.isPresent()) {
        attributeList.add(attribute.getCkAttribute());
      }
    }
    return attributeList.toArray(new CK_ATTRIBUTE[0]);
  }

  public Attribute getAttribute(long type) {
    for (Attribute attr : attributes) {
      if (attr.getType() == type) {
        return attr;
      }
    }
    return null;
  }

  public Boolean getBooleanAttrValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Long getLongAttrValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public Integer getIntAttrValue(long type) {
    Long value = getLongAttrValue(type);
    return value == null ? null : value.intValue();
  }

  public String getStringAttrValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((CharArrayAttribute) attr).getValue();
  }

  public byte[] getByteArrayAttrValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  @Override
  public String toString() {
    return toString(true, "");
  }

  public String toString(boolean withName, String indent) {
    StringBuilder sb = new StringBuilder(200);
    String indent2 = indent;
    if (withName) {
      sb.append(indent).append("Attribute Vector:");
      indent2 += "  ";
    }

    // sort the attributes to print
    List<Attribute> copy = new ArrayList<>(attributes);
    copy.sort(Comparator.comparingLong(Attribute::getType));

    int nameLen = 0;
    for (Attribute attribute : copy) {
      if (!attribute.isNullValue()) {
        nameLen = Math.max(nameLen, ckaCodeToName(attribute.getType()).length());
      }
    }

    nameLen = Math.min(nameLen, 30);

    for (Attribute attribute : copy) {
      if (attribute.isNullValue()) {
        continue;
      }

      if (sb.length() > 0) {
        sb.append("\n");
      }

      sb.append(attribute.toString(true, nameLen, indent2));
    }

    return sb.toString();
  }

  public byte[] acIssuer() {
    Attribute attr = getAttribute(CKA_AC_ISSUER);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector acIssuer(byte[] acIssuer) {
    return attr(CKA_AC_ISSUER, acIssuer);
  }

  public long[] allowedMechanisms() {
    Attribute attr = getAttribute(CKA_ALLOWED_MECHANISMS);
    return attr == null ? null : ((MechanismArrayAttribute) attr).getValue();
  }

  public AttributeVector allowedMechanisms(long[] allowedMechanisms) {
    return attr(CKA_ALLOWED_MECHANISMS, allowedMechanisms);
  }

  public Boolean alwaysAuthenticate() {
    Attribute attr = getAttribute(CKA_ALWAYS_AUTHENTICATE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector alwaysAuthenticate(Boolean alwaysAuthenticate) {
    return attr(CKA_ALWAYS_AUTHENTICATE, alwaysAuthenticate);
  }

  public Boolean alwaysSensitive() {
    Attribute attr = getAttribute(CKA_ALWAYS_SENSITIVE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector alwaysSensitive(Boolean alwaysSensitive) {
    return attr(CKA_ALWAYS_SENSITIVE, alwaysSensitive);
  }

  public String application() {
    Attribute attr = getAttribute(CKA_APPLICATION);
    return attr == null ? null : ((CharArrayAttribute) attr).getValue();
  }

  public AttributeVector application(String application) {
    return attr(CKA_APPLICATION, application);
  }

  public byte[] attrTypes() {
    Attribute attr = getAttribute(CKA_ATTR_TYPES);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector attrTypes(byte[] attrTypes) {
    return attr(CKA_ATTR_TYPES, attrTypes);
  }

  public BigInteger base() {
    Attribute attr = getAttribute(CKA_BASE);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public AttributeVector base(BigInteger base) {
    return attr(CKA_BASE, base);
  }

  public Integer bitsPerPixel() {
    Attribute attr = getAttribute(CKA_BITS_PER_PIXEL);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public AttributeVector bitsPerPixel(Integer bitsPerPixel) {
    return attr(CKA_BITS_PER_PIXEL, bitsPerPixel);
  }

  public Long certificateCategory() {
    Attribute attr = getAttribute(CKA_CERTIFICATE_CATEGORY);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector certificateCategory(Long certificateCategory) {
    return attr(CKA_CERTIFICATE_CATEGORY, certificateCategory);
  }

  public Long certificateType() {
    Attribute attr = getAttribute(CKA_CERTIFICATE_TYPE);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector certificateType(Long certificateType) {
    return attr(CKA_CERTIFICATE_TYPE, certificateType);
  }

  public Integer charColumns() {
    Attribute attr = getAttribute(CKA_CHAR_COLUMNS);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public AttributeVector charColumns(Integer charColumns) {
    return attr(CKA_CHAR_COLUMNS, charColumns);
  }

  public Integer charRows() {
    Attribute attr = getAttribute(CKA_CHAR_ROWS);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public AttributeVector charRows(Integer charRows) {
    return attr(CKA_CHAR_ROWS, charRows);
  }

  public String charSets() {
    Attribute attr = getAttribute(CKA_CHAR_SETS);
    return attr == null ? null : ((CharArrayAttribute) attr).getValue();
  }

  public AttributeVector charSets(String charSets) {
    return attr(CKA_CHAR_SETS, charSets);
  }

  public byte[] checkValue() {
    Attribute attr = getAttribute(CKA_CHECK_VALUE);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector checkValue(byte[] checkValue) {
    return attr(CKA_CHECK_VALUE, checkValue);
  }

  public Long class_() {
    Attribute attr = getAttribute(CKA_CLASS);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector class_(Long class_) {
    return attr(CKA_CLASS, class_);
  }

  public BigInteger coefficient() {
    Attribute attr = getAttribute(CKA_COEFFICIENT);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public AttributeVector coefficient(BigInteger coefficient) {
    return attr(CKA_COEFFICIENT, coefficient);
  }

  public Boolean color() {
    Attribute attr = getAttribute(CKA_COLOR);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector color(Boolean color) {
    return attr(CKA_COLOR, color);
  }

  public Boolean copyable() {
    Attribute attr = getAttribute(CKA_COPYABLE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector copyable(Boolean copyable) {
    return attr(CKA_COPYABLE, copyable);
  }

  public Boolean decrypt() {
    Attribute attr = getAttribute(CKA_DECRYPT);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector decrypt(Boolean decrypt) {
    return attr(CKA_DECRYPT, decrypt);
  }

  public byte[] defaultCmsAttributes() {
    Attribute attr = getAttribute(CKA_DEFAULT_CMS_ATTRIBUTES);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector defaultCmsAttributes(byte[] defaultCmsAttributes) {
    return attr(CKA_DEFAULT_CMS_ATTRIBUTES, defaultCmsAttributes);
  }

  public Boolean derive() {
    Attribute attr = getAttribute(CKA_DERIVE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector derive(Boolean derive) {
    return attr(CKA_DERIVE, derive);
  }

  public AttributeVector deriveTemplate() {
    Attribute attr = getAttribute(CKA_DERIVE_TEMPLATE);
    return attr == null ? null : ((AttributeArrayAttribute) attr).getValue();
  }

  public AttributeVector deriveTemplate(AttributeVector deriveTemplate) {
    return attr(CKA_DERIVE_TEMPLATE, deriveTemplate);
  }

  public Boolean destroyable() {
    Attribute attr = getAttribute(CKA_DESTROYABLE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector destroyable(Boolean destroyable) {
    return attr(CKA_DESTROYABLE, destroyable);
  }

  public byte[] ecParams() {
    Attribute attr = getAttribute(CKA_EC_PARAMS);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector ecParams(byte[] ecParams) {
    return attr(CKA_EC_PARAMS, ecParams);
  }

  public byte[] ecPoint() {
    Attribute attr = getAttribute(CKA_EC_POINT);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector ecPoint(byte[] ecPoint) {
    return attr(CKA_EC_POINT, ecPoint);
  }

  public String encodingMethods() {
    Attribute attr = getAttribute(CKA_ENCODING_METHODS);
    return attr == null ? null : ((CharArrayAttribute) attr).getValue();
  }

  public AttributeVector encodingMethods(String encodingMethods) {
    return attr(CKA_ENCODING_METHODS, encodingMethods);
  }

  public Boolean encrypt() {
    Attribute attr = getAttribute(CKA_ENCRYPT);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector encrypt(Boolean encrypt) {
    return attr(CKA_ENCRYPT, encrypt);
  }

  public Instant endDate() {
    Attribute attr = getAttribute(CKA_END_DATE);
    return attr == null ? null : ((DateAttribute) attr).getValue();
  }

  public AttributeVector endDate(Instant endDate) {
    return attr(CKA_END_DATE, endDate);
  }

  public BigInteger exponent1() {
    Attribute attr = getAttribute(CKA_EXPONENT_1);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public AttributeVector exponent1(BigInteger exponent1) {
    return attr(CKA_EXPONENT_1, exponent1);
  }

  public BigInteger exponent2() {
    Attribute attr = getAttribute(CKA_EXPONENT_2);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public AttributeVector exponent2(BigInteger exponent2) {
    return attr(CKA_EXPONENT_2, exponent2);
  }

  public Boolean extractable() {
    Attribute attr = getAttribute(CKA_EXTRACTABLE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector extractable(Boolean extractable) {
    return attr(CKA_EXTRACTABLE, extractable);
  }

  public byte[] gost28147Params() {
    Attribute attr = getAttribute(CKA_GOST28147_PARAMS);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector gost28147Params(byte[] gost28147Params) {
    return attr(CKA_GOST28147_PARAMS, gost28147Params);
  }

  public byte[] gostr3410Params() {
    Attribute attr = getAttribute(CKA_GOSTR3410_PARAMS);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector gostr3410Params(byte[] gostr3410Params) {
    return attr(CKA_GOSTR3410_PARAMS, gostr3410Params);
  }

  public byte[] gostr3411Params() {
    Attribute attr = getAttribute(CKA_GOSTR3411_PARAMS);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector gostr3411Params(byte[] gostr3411Params) {
    return attr(CKA_GOSTR3411_PARAMS, gostr3411Params);
  }

  public byte[] hashOfIssuerPublicKey() {
    Attribute attr = getAttribute(CKA_HASH_OF_ISSUER_PUBLIC_KEY);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector hashOfIssuerPublicKey(byte[] hashOfIssuerPublicKey) {
    return attr(CKA_HASH_OF_ISSUER_PUBLIC_KEY, hashOfIssuerPublicKey);
  }

  public byte[] hashOfSubjectPublicKey() {
    Attribute attr = getAttribute(CKA_HASH_OF_SUBJECT_PUBLIC_KEY);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector hashOfSubjectPublicKey(byte[] hashOfSubjectPublicKey) {
    return attr(CKA_HASH_OF_SUBJECT_PUBLIC_KEY, hashOfSubjectPublicKey);
  }

  public Boolean hasReset() {
    Attribute attr = getAttribute(CKA_HAS_RESET);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector hasReset(Boolean hasReset) {
    return attr(CKA_HAS_RESET, hasReset);
  }

  public Long hwFeatureType() {
    Attribute attr = getAttribute(CKA_HW_FEATURE_TYPE);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector hwFeatureType(Long hwFeatureType) {
    return attr(CKA_HW_FEATURE_TYPE, hwFeatureType);
  }

  public byte[] id() {
    Attribute attr = getAttribute(CKA_ID);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector id(byte[] id) {
    return attr(CKA_ID, id);
  }

  public byte[] issuer() {
    Attribute attr = getAttribute(CKA_ISSUER);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector issuer(byte[] issuer) {
    return attr(CKA_ISSUER, issuer);
  }

  public Long javaMidpSecurityDomain() {
    Attribute attr = getAttribute(CKA_JAVA_MIDP_SECURITY_DOMAIN);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector javaMidpSecurityDomain(Long javaMidpSecurityDomain) {
    return attr(CKA_JAVA_MIDP_SECURITY_DOMAIN, javaMidpSecurityDomain);
  }

  public Long keyGenMechanism() {
    Attribute attr = getAttribute(CKA_KEY_GEN_MECHANISM);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector keyGenMechanism(Long keyGenMechanism) {
    return attr(CKA_KEY_GEN_MECHANISM, keyGenMechanism);
  }

  public Long keyType() {
    Attribute attr = getAttribute(CKA_KEY_TYPE);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector keyType(Long keyType) {
    return attr(CKA_KEY_TYPE, keyType);
  }

  public String label() {
    Attribute attr = getAttribute(CKA_LABEL);
    return attr == null ? null : ((CharArrayAttribute) attr).getValue();
  }

  public AttributeVector label(String label) {
    return attr(CKA_LABEL, label);
  }

  public Boolean local() {
    Attribute attr = getAttribute(CKA_LOCAL);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector local(Boolean local) {
    return attr(CKA_LOCAL, local);
  }

  public Long mechanismType() {
    Attribute attr = getAttribute(CKA_MECHANISM_TYPE);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector mechanismType(Long mechanismType) {
    return attr(CKA_MECHANISM_TYPE, mechanismType);
  }

  public String mimeTypes() {
    Attribute attr = getAttribute(CKA_MIME_TYPES);
    return attr == null ? null : ((CharArrayAttribute) attr).getValue();
  }

  public AttributeVector mimeTypes(String mimeTypes) {
    return attr(CKA_MIME_TYPES, mimeTypes);
  }

  public Boolean modifiable() {
    Attribute attr = getAttribute(CKA_MODIFIABLE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector modifiable(Boolean modifiable) {
    return attr(CKA_MODIFIABLE, modifiable);
  }

  public BigInteger modulus() {
    Attribute attr = getAttribute(CKA_MODULUS);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public AttributeVector modulus(BigInteger modulus) {
    return attr(CKA_MODULUS, modulus);
  }

  public Integer modulusBits() {
    Attribute attr = getAttribute(CKA_MODULUS_BITS);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public AttributeVector modulusBits(Integer modulusBits) {
    return attr(CKA_MODULUS_BITS, modulusBits);
  }

  public Long nameHashAlgorithm() {
    Attribute attr = getAttribute(CKA_NAME_HASH_ALGORITHM);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector nameHashAlgorithm(Long nameHashAlgorithm) {
    return attr(CKA_NAME_HASH_ALGORITHM, nameHashAlgorithm);
  }

  public Boolean neverExtractable() {
    Attribute attr = getAttribute(CKA_NEVER_EXTRACTABLE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector neverExtractable(Boolean neverExtractable) {
    return attr(CKA_NEVER_EXTRACTABLE, neverExtractable);
  }

  public byte[] objectId() {
    Attribute attr = getAttribute(CKA_OBJECT_ID);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector objectId(byte[] objectId) {
    return attr(CKA_OBJECT_ID, objectId);
  }

  public Long otpChallengeRequirement() {
    Attribute attr = getAttribute(CKA_OTP_CHALLENGE_REQUIREMENT);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector otpChallengeRequirement(Long otpChallengeRequirement) {
    return attr(CKA_OTP_CHALLENGE_REQUIREMENT, otpChallengeRequirement);
  }

  public byte[] otpCounter() {
    Attribute attr = getAttribute(CKA_OTP_COUNTER);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector otpCounter(byte[] otpCounter) {
    return attr(CKA_OTP_COUNTER, otpCounter);
  }

  public Long otpCounterRequirement() {
    Attribute attr = getAttribute(CKA_OTP_COUNTER_REQUIREMENT);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector otpCounterRequirement(Long otpCounterRequirement) {
    return attr(CKA_OTP_COUNTER_REQUIREMENT, otpCounterRequirement);
  }

  public Long otpFormat() {
    Attribute attr = getAttribute(CKA_OTP_FORMAT);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector otpFormat(Long otpFormat) {
    return attr(CKA_OTP_FORMAT, otpFormat);
  }

  public Integer otpLength() {
    Attribute attr = getAttribute(CKA_OTP_LENGTH);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public AttributeVector otpLength(Integer otpLength) {
    return attr(CKA_OTP_LENGTH, otpLength);
  }

  public Long otpPinRequirement() {
    Attribute attr = getAttribute(CKA_OTP_PIN_REQUIREMENT);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector otpPinRequirement(Long otpPinRequirement) {
    return attr(CKA_OTP_PIN_REQUIREMENT, otpPinRequirement);
  }

  public String otpServiceIdentifier() {
    Attribute attr = getAttribute(CKA_OTP_SERVICE_IDENTIFIER);
    return attr == null ? null : ((CharArrayAttribute) attr).getValue();
  }

  public AttributeVector otpServiceIdentifier(String otpServiceIdentifier) {
    return attr(CKA_OTP_SERVICE_IDENTIFIER, otpServiceIdentifier);
  }

  public byte[] otpServiceLogo() {
    Attribute attr = getAttribute(CKA_OTP_SERVICE_LOGO);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector otpServiceLogo(byte[] otpServiceLogo) {
    return attr(CKA_OTP_SERVICE_LOGO, otpServiceLogo);
  }

  public String otpServiceLogoType() {
    Attribute attr = getAttribute(CKA_OTP_SERVICE_LOGO_TYPE);
    return attr == null ? null : ((CharArrayAttribute) attr).getValue();
  }

  public AttributeVector otpServiceLogoType(String otpServiceLogoType) {
    return attr(CKA_OTP_SERVICE_LOGO_TYPE, otpServiceLogoType);
  }

  public String otpTime() {
    Attribute attr = getAttribute(CKA_OTP_TIME);
    return attr == null ? null : ((CharArrayAttribute) attr).getValue();
  }

  public AttributeVector otpTime(String otpTime) {
    return attr(CKA_OTP_TIME, otpTime);
  }

  public Long otpTimeInterval() {
    Attribute attr = getAttribute(CKA_OTP_TIME_INTERVAL);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector otpTimeInterval(Long otpTimeInterval) {
    return attr(CKA_OTP_TIME_INTERVAL, otpTimeInterval);
  }

  public Long otpTimeRequirement() {
    Attribute attr = getAttribute(CKA_OTP_TIME_REQUIREMENT);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector otpTimeRequirement(Long otpTimeRequirement) {
    return attr(CKA_OTP_TIME_REQUIREMENT, otpTimeRequirement);
  }

  public Boolean otpUserFriendlyMode() {
    Attribute attr = getAttribute(CKA_OTP_USER_FRIENDLY_MODE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector otpUserFriendlyMode(Boolean otpUserFriendlyMode) {
    return attr(CKA_OTP_USER_FRIENDLY_MODE, otpUserFriendlyMode);
  }

  public String otpUserIdentifier() {
    Attribute attr = getAttribute(CKA_OTP_USER_IDENTIFIER);
    return attr == null ? null : ((CharArrayAttribute) attr).getValue();
  }

  public AttributeVector otpUserIdentifier(String otpUserIdentifier) {
    return attr(CKA_OTP_USER_IDENTIFIER, otpUserIdentifier);
  }

  public byte[] owner() {
    Attribute attr = getAttribute(CKA_OWNER);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector owner(byte[] owner) {
    return attr(CKA_OWNER, owner);
  }

  public Integer pixelX() {
    Attribute attr = getAttribute(CKA_PIXEL_X);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public AttributeVector pixelX(Integer pixelX) {
    return attr(CKA_PIXEL_X, pixelX);
  }

  public Integer pixelY() {
    Attribute attr = getAttribute(CKA_PIXEL_Y);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public AttributeVector pixelY(Integer pixelY) {
    return attr(CKA_PIXEL_Y, pixelY);
  }

  public BigInteger prime() {
    Attribute attr = getAttribute(CKA_PRIME);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public AttributeVector prime(BigInteger prime) {
    return attr(CKA_PRIME, prime);
  }

  public BigInteger prime1() {
    Attribute attr = getAttribute(CKA_PRIME_1);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public AttributeVector prime1(BigInteger prime1) {
    return attr(CKA_PRIME_1, prime1);
  }

  public BigInteger prime2() {
    Attribute attr = getAttribute(CKA_PRIME_2);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public AttributeVector prime2(BigInteger prime2) {
    return attr(CKA_PRIME_2, prime2);
  }

  public Integer primeBits() {
    Attribute attr = getAttribute(CKA_PRIME_BITS);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public AttributeVector primeBits(Integer primeBits) {
    return attr(CKA_PRIME_BITS, primeBits);
  }

  public Boolean private_() {
    Attribute attr = getAttribute(CKA_PRIVATE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector private_(Boolean private_) {
    return attr(CKA_PRIVATE, private_);
  }

  public BigInteger privateExponent() {
    Attribute attr = getAttribute(CKA_PRIVATE_EXPONENT);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public AttributeVector privateExponent(BigInteger privateExponent) {
    return attr(CKA_PRIVATE_EXPONENT, privateExponent);
  }

  public Long profileId() {
    Attribute attr = getAttribute(CKA_PROFILE_ID);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public AttributeVector profileId(Long profileId) {
    return attr(CKA_PROFILE_ID, profileId);
  }

  public BigInteger publicExponent() {
    Attribute attr = getAttribute(CKA_PUBLIC_EXPONENT);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public AttributeVector publicExponent(BigInteger publicExponent) {
    return attr(CKA_PUBLIC_EXPONENT, publicExponent);
  }

  public byte[] publicKeyInfo() {
    Attribute attr = getAttribute(CKA_PUBLIC_KEY_INFO);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector publicKeyInfo(byte[] publicKeyInfo) {
    return attr(CKA_PUBLIC_KEY_INFO, publicKeyInfo);
  }

  public byte[] requiredCmsAttributes() {
    Attribute attr = getAttribute(CKA_REQUIRED_CMS_ATTRIBUTES);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector requiredCmsAttributes(byte[] requiredCmsAttributes) {
    return attr(CKA_REQUIRED_CMS_ATTRIBUTES, requiredCmsAttributes);
  }

  public Boolean resetOnInit() {
    Attribute attr = getAttribute(CKA_RESET_ON_INIT);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector resetOnInit(Boolean resetOnInit) {
    return attr(CKA_RESET_ON_INIT, resetOnInit);
  }

  public Integer resolution() {
    Attribute attr = getAttribute(CKA_RESOLUTION);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public AttributeVector resolution(Integer resolution) {
    return attr(CKA_RESOLUTION, resolution);
  }

  public Boolean sensitive() {
    Attribute attr = getAttribute(CKA_SENSITIVE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector sensitive(Boolean sensitive) {
    return attr(CKA_SENSITIVE, sensitive);
  }

  public byte[] serialNumber() {
    Attribute attr = getAttribute(CKA_SERIAL_NUMBER);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector serialNumber(byte[] serialNumber) {
    return attr(CKA_SERIAL_NUMBER, serialNumber);
  }

  public Boolean sign() {
    Attribute attr = getAttribute(CKA_SIGN);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector sign(Boolean sign) {
    return attr(CKA_SIGN, sign);
  }

  public Boolean signRecover() {
    Attribute attr = getAttribute(CKA_SIGN_RECOVER);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector signRecover(Boolean signRecover) {
    return attr(CKA_SIGN_RECOVER, signRecover);
  }

  public Instant startDate() {
    Attribute attr = getAttribute(CKA_START_DATE);
    return attr == null ? null : ((DateAttribute) attr).getValue();
  }

  public AttributeVector startDate(Instant startDate) {
    return attr(CKA_START_DATE, startDate);
  }

  public byte[] subject() {
    Attribute attr = getAttribute(CKA_SUBJECT);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector subject(byte[] subject) {
    return attr(CKA_SUBJECT, subject);
  }

  public BigInteger subprime() {
    Attribute attr = getAttribute(CKA_SUBPRIME);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public AttributeVector subprime(BigInteger subprime) {
    return attr(CKA_SUBPRIME, subprime);
  }

  public Integer subprimeBits() {
    Attribute attr = getAttribute(CKA_SUBPRIME_BITS);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public AttributeVector subprimeBits(Integer subprimeBits) {
    return attr(CKA_SUBPRIME_BITS, subprimeBits);
  }

  public byte[] supportedCmsAttributes() {
    Attribute attr = getAttribute(CKA_SUPPORTED_CMS_ATTRIBUTES);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector supportedCmsAttributes(byte[] supportedCmsAttributes) {
    return attr(CKA_SUPPORTED_CMS_ATTRIBUTES, supportedCmsAttributes);
  }

  public Boolean token() {
    Attribute attr = getAttribute(CKA_TOKEN);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector token(Boolean token) {
    return attr(CKA_TOKEN, token);
  }

  public Boolean trusted() {
    Attribute attr = getAttribute(CKA_TRUSTED);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector trusted(Boolean trusted) {
    return attr(CKA_TRUSTED, trusted);
  }

  public String uniqueId() {
    Attribute attr = getAttribute(CKA_UNIQUE_ID);
    return attr == null ? null : ((CharArrayAttribute) attr).getValue();
  }

  public AttributeVector uniqueId(String uniqueId) {
    return attr(CKA_UNIQUE_ID, uniqueId);
  }

  public Boolean unwrap() {
    Attribute attr = getAttribute(CKA_UNWRAP);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector unwrap(Boolean unwrap) {
    return attr(CKA_UNWRAP, unwrap);
  }

  public AttributeVector unwrapTemplate() {
    Attribute attr = getAttribute(CKA_UNWRAP_TEMPLATE);
    return attr == null ? null : ((AttributeArrayAttribute) attr).getValue();
  }

  public AttributeVector unwrapTemplate(AttributeVector unwrapTemplate) {
    return attr(CKA_UNWRAP_TEMPLATE, unwrapTemplate);
  }

  public String url() {
    Attribute attr = getAttribute(CKA_URL);
    return attr == null ? null : ((CharArrayAttribute) attr).getValue();
  }

  public AttributeVector url(String url) {
    return attr(CKA_URL, url);
  }

  public byte[] value() {
    Attribute attr = getAttribute(CKA_VALUE);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public AttributeVector value(byte[] value) {
    return attr(CKA_VALUE, value);
  }

  public Integer valueBits() {
    Attribute attr = getAttribute(CKA_VALUE_BITS);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public AttributeVector valueBits(Integer valueBits) {
    return attr(CKA_VALUE_BITS, valueBits);
  }

  public Integer valueLen() {
    Attribute attr = getAttribute(CKA_VALUE_LEN);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public AttributeVector valueLen(Integer valueLen) {
    return attr(CKA_VALUE_LEN, valueLen);
  }

  public Boolean verify() {
    Attribute attr = getAttribute(CKA_VERIFY);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector verify(Boolean verify) {
    return attr(CKA_VERIFY, verify);
  }

  public Boolean verifyRecover() {
    Attribute attr = getAttribute(CKA_VERIFY_RECOVER);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector verifyRecover(Boolean verifyRecover) {
    return attr(CKA_VERIFY_RECOVER, verifyRecover);
  }

  public Boolean wrap() {
    Attribute attr = getAttribute(CKA_WRAP);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector wrap(Boolean wrap) {
    return attr(CKA_WRAP, wrap);
  }

  public AttributeVector wrapTemplate() {
    Attribute attr = getAttribute(CKA_WRAP_TEMPLATE);
    return attr == null ? null : ((AttributeArrayAttribute) attr).getValue();
  }

  public AttributeVector wrapTemplate(AttributeVector wrapTemplate) {
    return attr(CKA_WRAP_TEMPLATE, wrapTemplate);
  }

  public Boolean wrapWithTrusted() {
    Attribute attr = getAttribute(CKA_WRAP_WITH_TRUSTED);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public AttributeVector wrapWithTrusted(Boolean wrapWithTrusted) {
    return attr(CKA_WRAP_WITH_TRUSTED, wrapWithTrusted);
  }

  public AttributeVector attributesAsSensitive(long... ckaTypes) {
    for (Attribute attr : attributes) {
      for (long type : ckaTypes) {
        if (attr.type() == type) {
          attr.sensitive(true);
          break;
        }
      }
    }
    return this;
  }

}
