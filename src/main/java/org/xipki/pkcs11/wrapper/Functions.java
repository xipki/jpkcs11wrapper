// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This class contains only static methods. It is the place for all functions
 * that are used by several classes in this package.
 *
 * @author Lijun Liao (xipki)
 */
public class Functions {

  private static class Hex {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();
    private static final char[] UPPER_DIGITS = "0123456789ABCDEF".toCharArray();

    private static final int[] LINTS = new int['f' + 1];
    private static final int[] HINTS = new int[LINTS.length];

    static {
      for (int i = 0; i < DIGITS.length; i++) {
        LINTS[DIGITS[i]] = i;
      }

      for (int i = 10; i < UPPER_DIGITS.length; i++) {
        LINTS[UPPER_DIGITS[i]] = i;
      }

      for (int i = 0; i < LINTS.length; i++) {
        HINTS[i] = LINTS[i] << 4;
      }
    }

    public static String encode(byte[] data, int ofs, int len) {
      char[] out = new char[len << 1];

      // two characters from the hex value.
      int endOfs = ofs + len;
      for (int i = ofs, j = 0; i < endOfs; i++) {
        out[j++] = DIGITS[(0xF0 & data[i]) >>> 4];
        out[j++] = DIGITS[0x0F & data[i]];
      }

      return new String(out);
    }

    public static byte[] decode(String hex) {
      char[] data = hex.toCharArray();
      int len = data.length;

      if ((len & 0x01) != 0) {
        throw new IllegalArgumentException("Odd number of characters.");
      }

      byte[] out = new byte[len >> 1];

      // two characters from the hex value.
      for (int i = 0, j = 0; j < len; i++) {
        out[i] = (byte) (HINTS[data[j++]] | LINTS[data[j++]]);
      }

      return out;
    }

  }

  private static class ECInfo {
    int fieldSize;
    int orderSize;
    int orderBitLength;
    String oid;
    String[] names;
    byte[] order;
    byte[] baseX;
  }

  private static final Map<Long, String> hashMechCodeToHashNames;

  private static final Map<String, ECInfo> ecParamsInfoMap;

  private static final Set<String> edwardsMontgomeryEcParams;

  static {
    hashMechCodeToHashNames = new HashMap<>();
    hashMechCodeToHashNames.put(CKM_SHA_1, "SHA1");
    hashMechCodeToHashNames.put(CKM_SHA224, "SHA224");
    hashMechCodeToHashNames.put(CKM_SHA256, "SHA256");
    hashMechCodeToHashNames.put(CKM_SHA384, "SHA384");
    hashMechCodeToHashNames.put(CKM_SHA512, "SHA512");
    hashMechCodeToHashNames.put(CKM_SHA512_224, "SHA512/224");
    hashMechCodeToHashNames.put(CKM_SHA512_256, "SHA512/256");
    hashMechCodeToHashNames.put(CKM_SHA3_224, "SHA3-224");
    hashMechCodeToHashNames.put(CKM_SHA3_256, "SHA3-256");
    hashMechCodeToHashNames.put(CKM_SHA3_384, "SHA3-384");
    hashMechCodeToHashNames.put(CKM_SHA3_512, "SHA3-512");

    edwardsMontgomeryEcParams = new HashSet<>(6);
    // X25519 (1.3.101.110)
    edwardsMontgomeryEcParams.add("06032b656e");
    // X448 (1.3.101.111)
    edwardsMontgomeryEcParams.add("06032b656f");
    // ED25519 (1.3.101.112)
    edwardsMontgomeryEcParams.add("06032b6570");
    // ED448 (1.3.101.113)
    edwardsMontgomeryEcParams.add("06032b6571");

    ecParamsInfoMap = new HashMap<>(120);

    String propFile = "org/xipki/pkcs11/wrapper/EC.properties";
    Properties props = new Properties();
    try {
      props.load(Functions.class.getClassLoader().getResourceAsStream(propFile));
      ByteArrayOutputStream buffer = new ByteArrayOutputStream(100);
      for (String name : props.stringPropertyNames()) {
        ECInfo ecInfo = new ECInfo();
        ecInfo.oid = name.trim();

        if (ecParamsInfoMap.containsKey(name)) {
          throw new IllegalStateException("duplicated definition of " + name);
        }

        byte[] ecParams = encodeOid(buffer, ecInfo.oid);

        String[] values = props.getProperty(name).split(",");
        ecInfo.names = values[0].toUpperCase(Locale.ROOT).split(":");
        ecInfo.fieldSize = (Integer.parseInt(values[1]) + 7) / 8;
        ecInfo.orderBitLength = Integer.parseInt(values[2]);
        ecInfo.orderSize = (ecInfo.orderBitLength + 7) / 8;

        String str = values[3];
        if (!str.isEmpty() && !"-".equals(str)) {
          ecInfo.order = new BigInteger(str, 16).toByteArray();
        }

        str = values[4];
        if (!str.isEmpty() && !"-".equals(str)) {
          ecInfo.baseX = new BigInteger(str, 16).toByteArray();
        }

        String hexEcParams = Hex.encode(ecParams, 0, ecParams.length);

        ecParamsInfoMap.put(hexEcParams, ecInfo);
      }
    } catch (Throwable t) {
      throw new IllegalStateException("error reading properties file " + propFile + ": " + t.getMessage());
    }
  }

  public static byte[] encodeOid(String oid) {
    return encodeOid(new ByteArrayOutputStream(10), oid);
  }

  private static byte[] encodeOid(ByteArrayOutputStream out, String oid) {
    out.reset();
    String[] nodes = oid.split("\\.");
    out.write(0x06);
    out.write(0); // place holder for length

    // first two nodes
    int node0 = Integer.parseInt(nodes[0]);
    int node1 = Integer.parseInt(nodes[1]);
    boolean valid = ((node0 == 0 || node0 == 1) && (node1 < 40)) || node0 == 2;
    if (!valid) {
      throw new IllegalArgumentException("invalid oid " + oid);
    }

    int nodeValue = node0 * 40 + node1;
    encodeOidNode(out, nodeValue);

    for (int i = 2; i < nodes.length; i++) {
      int v = Integer.parseInt(nodes[i]);
      encodeOidNode(out, v);
    }

    byte[] is = out.toByteArray();
    if (is.length - 2 > 127) {
      throw new IllegalStateException("should not reach here, OID too long");
    }
    is[1] = (byte) (is.length - 2);
    return is;
  }

  private static void encodeOidNode(ByteArrayOutputStream out, int nodeValue) {
    if (nodeValue < 128) {
      out.write(nodeValue);
    } else {
      int bitLen = BigInteger.valueOf(nodeValue).bitLength();
      // bitLen=8, numBytes=2, shiftBits = 1
      int numBytes = (bitLen + 6) / 7;
      int shiftBits = bitLen - (numBytes - 1) * 7;
      for (int j = 0; j < numBytes; j++) {
        int k = 0x7F & (nodeValue >> (bitLen - shiftBits - 7 * j));
        if (j != numBytes - 1) {
          k |= 0x80;
        }
        out.write(k);
      }
    }
  }

  public static String getHashAlgName(long hashMechanism) {
    return hashMechCodeToHashNames.get(hashMechanism);
  }

  public static byte[] asUnsignedByteArray(java.math.BigInteger bn) {
    byte[] bytes = bn.toByteArray();
    return bytes[0] != 0 ? bytes : Arrays.copyOfRange(bytes, 1, bytes.length);
  }

  /**
   * Converts a long value to a lower-case hexadecimal String of length 16. Includes
   * leading zeros if necessary.
   *
   * @param value
   *          The long value to be converted.
   * @return The hexadecimal string representation of the long value.
   */
  public static String toFullHex(long value) {
    return toFullHex(value, false);
  }

  /**
   * Converts a long value to an upper-case hexadecimal String of length 16. Includes
   * leading zeros if necessary.
   *
   * @param value
   *          The long value to be converted.
   * @return The hexadecimal string representation of the long value.
   */
  public static String toFullHexUpper(long value) {
    return toFullHex(value, true);
  }

  private static String toFullHex(long value, boolean upperCase) {
    long currentValue = value;
    StringBuilder stringBuffer = new StringBuilder(16);
    final int size = value > 0xFFFFFFFFL ? 16 : 8;
    for (int j = 0; j < size; j++) {
      int currentDigit = (int) currentValue & 0xf;
      stringBuffer.append((upperCase ? Hex.UPPER_DIGITS : Hex.DIGITS)[currentDigit]);
      currentValue >>>= 4;
    }

    return stringBuffer.reverse().toString();
  }

  /**
   * Converts a byte array to a hexadecimal String. Each byte is presented by
   * its two digit hex-code; 0x0A -&gt; "0a", 0x00 -&gt; "00". No leading "0x"
   * is included in the result.
   *
   * @param value
   *          the byte array to be converted
   * @return the hexadecimal string representation of the byte array
   */
  public static String toHex(byte[] value) {
    return Hex.encode(value, 0, value.length);
  }

  public static String toHex(byte[] value, int ofs, int len) {
    return Hex.encode(value, ofs, len);
  }

  public static byte[] decodeHex(String encoded) {
    return Hex.decode(encoded);
  }

  public static Long parseLong(String text) {
    if (text.startsWith("0x") || text.startsWith("0X")) {
      return Long.parseLong(text.substring(2), 16);
    } else {
      boolean isNumber = true;
      boolean withSign = text.startsWith("-");
      for (int i = (withSign ? 1 : 0); i < text.length(); i++) {
        char c = text.charAt(i);
        if (c > '9' || c < '0') {
          isNumber = false;
          break;
        }
      }

      if (isNumber) {
        return Long.parseLong(text);
      } else {
        return null;
      }
    }
  }

  public static <T> T requireNonNull(String paramName, T param) {
    if (param == null) {
      throw new NullPointerException("Argument '" + paramName + "' must not be null.");
    }

    return param;
  }

  public static int requireRange(String name, int argument, int min, int max) {
    if (argument < min || argument > max) {
      throw new IllegalArgumentException(String.format(
          "%s may not be out of the range [%d, %d]: %d", name, min, max, argument));
    }
    return argument;
  }

  public static int requireAmong(String name, int argument, int... candidates) {
    for (int candidate : candidates) {
      if (argument == candidate) {
        return argument;
      }
    }

    throw new IllegalArgumentException(name + " is not among " + Arrays.toString(candidates) + ": " + argument);
  }

  public static String toStringFlags(Category category, String prefix, long flags, long... flagMasks) {
    // initialize the indent for non-first lines.
    char[] indentChars = new char[prefix.length() + 1];
    Arrays.fill(indentChars, ' ');
    String indent = new String(indentChars);

    ArrayList<Long> sortedMasks = new ArrayList<>(flagMasks.length);
    for (long flagMask : flagMasks) {
      sortedMasks.add(flagMask);
    }
    java.util.Collections.sort(sortedMasks);

    boolean first = true;
    List<String> lines = new LinkedList<>();

    String line = prefix + "0x" + toFullHex(flags) + " (";
    for (long flagMask : sortedMasks) {
      if ((flags & flagMask) == 0L) {
        continue;
      }

      String thisEntry = first ? "" : " | ";

      if (first) {
        first = false;
      }

      thisEntry += codeToName(category, flagMask).substring(4); // 4 = "CKF_".length
      if (line.length() + thisEntry.length() > 100) {
        lines.add(line);
        line = indent;
      }
      line += thisEntry;
    }

    if (line.length() > indentChars.length) {
      lines.add(line);
    }

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < lines.size(); i++) {
      if (i != 0) {
        sb.append("\n");
      }

      sb.append(lines.get(i));
    }
    return sb.append(")").toString();
  }

  public static byte[] getEcParams(BigInteger order, BigInteger baseX) {
    byte[] orderBytes = order.toByteArray();
    byte[] baseXBytes = baseX.toByteArray();
    for (Map.Entry<String, ECInfo> m : ecParamsInfoMap.entrySet()) {
      ECInfo ei = m.getValue();
      if (Arrays.equals(ei.order, orderBytes) && Arrays.equals(ei.baseX, baseXBytes)) {
        return Hex.decode(m.getKey());
      }
    }
    return null;
  }

  public static Integer getCurveOrderBitLength(byte[] ecParams) {
    ECInfo ecInfo = ecParamsInfoMap.get(Hex.encode(ecParams, 0, ecParams.length));
    return (ecInfo == null) ? null : ecInfo.orderBitLength;
  }

  public static String getCurveName(byte[] ecParams) {
    ECInfo ecInfo = ecParamsInfoMap.get(Hex.encode(ecParams, 0, ecParams.length));
    return (ecInfo == null) ? null : ecInfo.names[0];
  }

  public static String[] getCurveNames(byte[] ecParams) {
    ECInfo ecInfo = ecParamsInfoMap.get(Hex.encode(ecParams, 0, ecParams.length));
    return (ecInfo == null) ? null : ecInfo.names.clone();
  }

  public static String decodeOid(byte[] encoded) {
    final int len = encoded.length;
    if (len < 3 || encoded[0] != 0x06 ||
        (0xFF & encoded[1]) != len - 2 || (encoded[len - 1] & 0x80) != 0) {
      throw new IllegalArgumentException("invalid ecParams");
    }

    StringBuilder sb = new StringBuilder(len + 5);

    int offset = 2;
    boolean start = true;
    while (offset < len) {
      if (!start) {
        sb.append(".");
      }
      offset = readNode(sb, encoded, offset, start);
      start = false;
    }

    if (offset != len) {
      throw new IllegalArgumentException("encoded too long");
    }

    return sb.toString();
  }

  /*
   * returns the new offset.
   */
  private static int readNode(StringBuilder sb, byte[] values, int off, boolean start) {
    int nodeValue = 0;
    while (true) {
      int v = 0xff & values[off++];
      boolean hasFurther = (v & 0x80) != 0;
      nodeValue <<= 7;
      nodeValue += (v & 0x7F);
      if (!hasFurther) {
        break;
      }
    }

    if (start) {
      if (nodeValue < 40) {
        sb.append("0.").append(nodeValue);
      } else if (nodeValue < 80) {
        sb.append("1.").append(nodeValue - 40);
      } else {
        sb.append("2.").append(nodeValue - 80);
      }
    } else {
      sb.append(nodeValue);
    }

    return off;
  }

  static Integer getECFieldSize(byte[] ecParams) {
    ECInfo ecInfo = ecParamsInfoMap.get(Hex.encode(ecParams, 0, ecParams.length));
    return (ecInfo == null) ? null : ecInfo.fieldSize;
  }

  static byte[] fixECDSASignature(byte[] sig, byte[] ecParams) {
    ECInfo ecInfo = ecParamsInfoMap.get(Hex.encode(ecParams, 0, ecParams.length));
    return (ecInfo == null) ? sig : fixECDSASignature(sig, ecInfo.orderSize);
  }

  static byte[] fixECParams(byte[] ecParams) {
    try {
      AtomicInteger numLenBytes = new AtomicInteger();

      // some HSMs, e.g. SoftHSM may return the ASN.1 string, e.g. edwards25519 for ED25519.
      int tag = 0xFF & ecParams[0];
      if (tag == 12 || tag == 19) { // 12: UTF8 String, 19: Printable String
        int offset = 1;
        int len = getDerLen(ecParams, offset, numLenBytes);
        offset += numLenBytes.get();

        if (offset + len == ecParams.length) {
          String curveName = new String(ecParams, offset, len, StandardCharsets.UTF_8).trim().toUpperCase(Locale.ROOT);
          for (Map.Entry<String, ECInfo> m : ecParamsInfoMap.entrySet()) {
            for (String name : m.getValue().names) {
              if (name.equals(curveName)) {
                return decodeHex(m.getKey());
              }
            }
          }
        }

        return ecParams;
      }

      if (tag == 0x30) { // ECParameters
        /*
        ECParameters ::= SEQUENCE {
          version         INTEGER { ecpVer1(1) } (ecpVer1),
          fieldID         FieldID {{FieldTypes}},
          curve           X9Curve,
          base            X9ECPoint,
          order           INTEGER,
          cofactor        INTEGER OPTIONAL
        }
        */

        int offset = 1;
        int len = getDerLen(ecParams, offset, numLenBytes);
        offset += numLenBytes.get();

        // outside SEQUENCE
        if (offset + len != ecParams.length) {
          return ecParams;
        }

        offset = getOffsetOfNextField(ecParams, offset); // version
        offset = getOffsetOfNextField(ecParams, offset); // fieldID
        offset = getOffsetOfNextField(ecParams, offset); // curve

        // base
        if (ecParams[offset++] != 0x04) {
          return ecParams;
        }
        len = getDerLen(ecParams, offset, numLenBytes);
        offset += numLenBytes.get();
        int nextOffset = offset + len;

        byte pointEncoding = ecParams[offset++];

        byte[] baseX;
        if (pointEncoding == 0x04) {
          baseX = Arrays.copyOfRange(ecParams, offset, offset + (len - 1) / 2);
        } else if (pointEncoding == 0x02 || pointEncoding == 0x03) {
          baseX = Arrays.copyOfRange(ecParams, offset, offset + len - 1);
        } else {
          // throw new TokenException("unknown ECPoint encoding " + pointEncoding);
          return ecParams;
        }

        // fix baseX
        if ((baseX[0] & 0x80) != 0) {
          byte[] newBaseX = new byte[1 + baseX.length];
          System.arraycopy(baseX, 0, newBaseX, 1,  baseX.length);
          baseX = newBaseX;
        } else if (baseX[0] == 0 && (baseX[1] & 0x80) == 0) {
          baseX = new BigInteger(1, baseX).toByteArray();
        }

        offset = nextOffset;

        // order
        if (ecParams[offset++] != 0x02) {
          return ecParams;
        }
        len = getDerLen(ecParams, offset, numLenBytes);
        offset += numLenBytes.get();
        byte[] order = Arrays.copyOfRange(ecParams, offset, offset + len);

        for (Map.Entry<String, ECInfo> m : ecParamsInfoMap.entrySet()) {
          ECInfo ei = m.getValue();
          if (ei.order == null) {
            continue;
          }

          if (Arrays.equals(ei.order, order) && Arrays.equals(ei.baseX, baseX)) {
            return decodeHex(m.getKey());
          }
        }
      }

      return ecParams;
    } catch (Exception e) {
      return ecParams;
    }
  }

  public static byte[] dsaSigPlainToX962(byte[] sig) {
    if (sig.length % 2 != 0) {
      // invalid format, just returns sig.
      return sig;
    }

    int rOrSLen = sig.length / 2;

    //----- determine the length of the DER-encoded R
    int derRLen = rOrSLen;
    // remove the leading zeros.
    for (int i = 0; i < rOrSLen; i++) {
      if (sig[i] == 0) {
        derRLen--;
      } else {
        break;
      }
    }

    // add one zero if the first byte is greater than 127.
    if ((sig[rOrSLen - derRLen] & 0x80) != 0) {
      derRLen++;
    }

    //----- determine the length of the DER-encoded S
    int derSLen = rOrSLen;
    // remove the leading zeros.
    for (int i = 0; i < rOrSLen; i++) {
      if (sig[rOrSLen + i] == 0) {
        derSLen--;
      } else {
        break;
      }
    }

    // add one zero if the first byte is greater than 127.
    if ((sig[sig.length - derSLen] & 0x80) != 0) {
      derSLen++;
    }

    int contentLen = 2 + derRLen + 2 + derSLen;
    int numBytesForContentLen = 1;
    if (contentLen > 127) {
      numBytesForContentLen++;
    }

    // construct the result
    byte[] res = new byte[1 + numBytesForContentLen + contentLen];
    res[0] = 0x30;

    // length
    int offset = 1;
    if (numBytesForContentLen > 1) {
      res[offset++] = (byte) 0x81;
    }
    res[offset++] = (byte) contentLen;

    // R
    res[offset++] = 0x02;
    res[offset++] = (byte) derRLen;

    if (derRLen >= rOrSLen) {
      System.arraycopy(sig, 0, res, offset + derRLen - rOrSLen, rOrSLen);
    } else {
      System.arraycopy(sig, rOrSLen - derRLen, res, offset, derRLen);
    }
    offset += derRLen;

    // S
    res[offset++] = 0x02;
    res[offset++] = (byte) derSLen;

    if (derSLen >= rOrSLen) {
      System.arraycopy(sig, rOrSLen, res, offset + derSLen - rOrSLen, rOrSLen);
    } else {
      System.arraycopy(sig, sig.length - derSLen, res, offset, derSLen);
    }

    return res;
  }

  static byte[] fixECDSASignature(byte[] sig, int rOrSLen) {
    if (sig.length == 2 * rOrSLen || sig[0] != 0x30) {
      return sig;
    }
    return dsaSigX962ToPlain(sig, rOrSLen);
  }

  public static byte[] dsaSigX962ToPlain(byte[] sig, int rOrSLen) {
    try {
      AtomicInteger numLenBytes = new AtomicInteger();

      int ofs = 1;
      int len = getDerLen(sig, ofs, numLenBytes);
      ofs += numLenBytes.get();

      if (len == 0 || ofs + len != sig.length) {
        return sig;
      }

      // first integer, r
      if (sig[ofs++] != 0x02) {
        return sig;
      }

      int rLen = getDerLen(sig, ofs, numLenBytes);
      ofs += numLenBytes.get();

      byte[] r = Arrays.copyOfRange(sig, ofs, ofs + rLen);
      ofs += rLen;

      // second integer, s
      if (sig[ofs++] != 0x02) {
        return sig;
      }

      int sLen = getDerLen(sig, ofs, numLenBytes);
      ofs += numLenBytes.get();

      if (ofs + sLen != sig.length) {
        return sig;
      }

      byte[] s = Arrays.copyOfRange(sig, ofs, sig.length);

      // remove leading zero
      if (r[0] == 0) {
        r = Arrays.copyOfRange(r, 1, r.length);
      }

      if (s[0] == 0) {
        s = Arrays.copyOfRange(s, 1, s.length);
      }

      if (r.length > rOrSLen || s.length > rOrSLen) {
        // we can not fix it.
        return sig;
      }

      byte[] rs = new byte[2 * rOrSLen];
      System.arraycopy(r, 0, rs, rOrSLen - r.length, r.length);
      System.arraycopy(s, 0, rs, rs.length - s.length, s.length);
      return rs;
    } catch (Exception e) {
      return sig;
    }
  }

  public static String toString(String prefix, byte[] bytes) {
    final int numPerLine = 40;
    final int len = bytes.length;
    int indentLen = prefix.length();
    if (indentLen > 0 && prefix.charAt(0) == '\n') {
      indentLen--;
    }

    char[] indentChars = new char[indentLen];
    Arrays.fill(indentChars, ' ');
    String indent = "\n" + new String(indentChars);

    StringBuilder sb = new StringBuilder(5 * (len + numPerLine - 1) / numPerLine + 4 * bytes.length);
    for (int ofs = 0; ofs < len; ofs += numPerLine) {
      int num = Math.min(numPerLine, len - ofs);
      sb.append(ofs == 0 ? prefix : indent).append(toHex(bytes, ofs, num));
    }
    return sb.toString();
  }

  // remove the outer ASN.1 tag and length
  static byte[] getCoreECPoint(byte[] ecPoint) {
    try {
      if (ecPoint[0] == 0x04) {
        return getOctetsFromASN1OctetString(ecPoint);
      } else if (ecPoint[0] == 0x03){
        return getOctetsFromASN1BitString(ecPoint);
      } else {
        return ecPoint;
      }
    } catch (TokenException e) {
      return ecPoint;
    }
  }

  // remove the outer ASN.1 tag and length, and try to handle ECPoint that is not
  // pKCS#11 standard conform.
  static byte[] getCoreECPoint(byte[] ecPoint, byte[] ecParams) {
    if (ecParams == null) {
      return getCoreECPoint(ecPoint);
    }

    int len = ecPoint.length;

    if (len > 0xFFF0) {
      // too long, should not happen. Just try to remove the ASN.1 tag and length.
      return getCoreECPoint(ecPoint);
    }

    String hexEcParams = Hex.encode(ecParams, 0, ecParams.length);
    ECInfo ecInfo = ecParamsInfoMap.get(hexEcParams);

    if (ecInfo == null) {
      // Unknown curve. Just try to remove the ASN.1 tag and length.
      return getCoreECPoint(ecPoint);
    }

    int fieldSize = ecInfo.fieldSize;
    if (edwardsMontgomeryEcParams.contains(hexEcParams)) {
      // edwards or montgomery curve
      return (len == fieldSize) ? ecPoint : getCoreECPoint(ecPoint);
    }

    // weierstrauss curve.
    if (ecPoint.length == 2 * fieldSize) {
      // HSM returns x_coordinate || y_coordinate
      byte[] ecPoint2 = new byte[1 + ecPoint.length];
      ecPoint2[0] = (byte) 4;
      System.arraycopy(ecPoint, 0, ecPoint2, 1, ecPoint.length);
      return ecPoint2;
    } else {
      byte encodingByte = ecPoint[0];
      if (encodingByte == 0x04) {
        if (len == 1 + 2 * fieldSize) {
          // HSM returns 04 || x_coordinate || y_coordinate
          return ecPoint;
        }
      } else if (encodingByte == 0x02 || encodingByte == 0x03) {
        if (len == 1 + fieldSize) {
          // HSM returns <02 or 03> || x_coordinate
          return ecPoint;
        }
      }
    }

    return getCoreECPoint(ecPoint);
  }

  public static byte[] getOctetsFromASN1OctetString(byte[] encoded) throws TokenException {
    if (encoded[0] != 0x04) {
      throw new TokenException("encoded is not a valid ASN.1 octet string");
    }

    AtomicInteger numLenBytes = new AtomicInteger();
    int len = getDerLen(encoded, 1, numLenBytes);
    if (1 + numLenBytes.get() + len != encoded.length) {
      throw new TokenException("encoded is not a valid ASN.1 octet string");
    }
    return Arrays.copyOfRange(encoded, 1 + numLenBytes.get(), encoded.length);
  }

  public static byte[] getOctetsFromASN1BitString(byte[] encoded) throws TokenException {
    if (encoded[0] != 0x03) {
      throw new TokenException("encoded is not a valid ASN.1 bit string");
    }

    AtomicInteger numLenBytes = new AtomicInteger();
    int len = getDerLen(encoded, 1, numLenBytes);
    if (1 + numLenBytes.get() + len != encoded.length) {
      throw new TokenException("encoded is not a valid ASN.1 octet string");
    }

    // ignore the first byte after the length.s
    return Arrays.copyOfRange(encoded, 1 + numLenBytes.get() + 1, encoded.length);
  }

  public static byte[] toOctetOrBitString(byte[] bytes, boolean isBitString) {
    int len = bytes.length;

    int numLenBytes = (len <= 0x7F) ? 1 : (len <= 0xFF) ? 2 : (len <= 0xFFFF) ? 3 : 4;
    int size = 1 + numLenBytes + len;
    if (isBitString) {
      size++;
    }

    byte[] ret = new byte[size];
    int off = 0;
    ret[off++] = isBitString ? (byte) 0x03 : (byte) 0x04;

    if (numLenBytes == 2) {
      ret[off++] = (byte) 0x81;
    } else if (numLenBytes == 3) {
      ret[off++] = (byte) 0x82;
      ret[off++] = (byte) (len >> 8);
    } else if (numLenBytes == 4) {
      ret[off++] = (byte) 0x83;
      ret[off++] = (byte) (len >> 16);
      ret[off++] = (byte) (len >> 8);
    }
    ret[off++] = (byte) len;

    if (isBitString) {
      ret[off++] = 0;
    }

    System.arraycopy(bytes, 0, ret, off, bytes.length);
    return ret;
  }

  private static int getOffsetOfNextField(byte[] bytes, int offset) throws TokenException {
    offset++; // tag
    AtomicInteger numLenBytes = new AtomicInteger();
    int len = getDerLen(bytes, offset, numLenBytes);
    return offset + numLenBytes.get() + len;
  }

  private static int getDerLen(byte[] bytes, int ofs, AtomicInteger numLenBytes) throws TokenException {
    int origOfs = ofs;
    int b = 0xFF & bytes[ofs++];
    int len = ((b & 0x80) == 0) ? b
        : (b == 0x81) ?  0xFF & bytes[ofs++]
        : (b == 0x82) ? (0xFF & bytes[ofs++]) <<  8 | (0xFF & bytes[ofs++])
        : (b == 0x83) ? (0xFF & bytes[ofs++]) << 16 | 0xFF & (0xFF & bytes[ofs++]) << 8 | (0xFF & bytes[ofs++])
        : (b == 0x84) ? (0xFF & bytes[ofs++]) << 24 | (0xFF & bytes[ofs++]) << 16
                        | 0xFF & (0xFF & bytes[ofs++]) << 8 | (0xFF & bytes[ofs++])
        : -1;
    if (len == -1) {
      throw new TokenException("invalid DER encoded bytes");
    }

    numLenBytes.set(ofs - origOfs);
    return len;
  }

}
