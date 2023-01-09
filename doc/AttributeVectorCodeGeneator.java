import org.xipki.pkcs11.Functions;
import org.xipki.pkcs11.objects.*;

import java.util.*;

import static org.xipki.pkcs11.PKCS11Constants.*;

public class AttributeVectorCodeGeneator {

  private static List<Long> bigIntCodes = Arrays.asList(
      CKA_BASE,
      CKA_COEFFICIENT,
      CKA_EXPONENT_1,
      CKA_EXPONENT_2,
      CKA_MODULUS,
      CKA_PRIME,
      CKA_PRIME_1,
      CKA_PRIME_2,
      CKA_PRIVATE_EXPONENT,
      CKA_PUBLIC_EXPONENT,
      CKA_SUBPRIME
  );

  private static List<Long> intCodes = Arrays.asList(
      CKA_MODULUS_BITS,
      CKA_PRIME_BITS,
      CKA_SUBPRIME_BITS,
      CKA_VALUE_BITS,
      CKA_VALUE_LEN,
      CKA_OTP_LENGTH,
      CKA_PIXEL_X,
      CKA_PIXEL_Y,
      CKA_RESOLUTION,
      CKA_CHAR_ROWS,
      CKA_CHAR_COLUMNS,
      CKA_BITS_PER_PIXEL
  );

  private static List<String> reservedWords = Arrays.asList(
      "class", "private", "public"
  );

  public static void main(String[] args) {
    Set<Long> codes = Functions.ckaCodeNameMap.codes();

    List<String> names = new ArrayList<>(codes.size());
    for (Long code : codes) {
      names.add(Functions.ckaCodeToName(code));
    }

    Collections.sort(names);

    for (String name : names) {
      String[] tokens = name.substring("CKA_".length()).split("_");
      String paramName = tokens[0].toLowerCase();
      for (int i = 1; i < tokens.length; i++) {
        String s = tokens[i].toLowerCase();
        char firstChar = s.charAt(0);
        if (firstChar >= '0' && firstChar <= '9') {
          paramName += firstChar;
        } else {
          paramName += Character.toUpperCase(firstChar);
        }

        if (s.length() > 0) {
          paramName += s.substring(1);
        }
      }

      if (reservedWords.contains(paramName)) {
        paramName += "_";
      }

      long code = Functions.ckaNameToCode(name);
      Class<?> clazz = Attribute.attributeClasses.get(code);
      String type =
          clazz == BooleanAttribute.class ? "Boolean"
              : clazz == LongAttribute.class ? "Long"
              : clazz == CharArrayAttribute.class ? "String"
              : clazz == ByteArrayAttribute.class ? "byte[]"
              : clazz == DateAttribute.class ? "Date"
              : clazz == MechanismAttribute.class ? "Long"
              : clazz == MechanismArrayAttribute.class ? "long[]"
              : clazz == AttributeArrayAttribute.class ? "AttributeVector"
              : null;
      if (type == null) {
        throw new IllegalStateException("unknown name " + name);
      }

      if ("Long".equals(type)) {
        if (intCodes.contains(code)) {
          type = "Integer";
        }
      } else if ("byte[]".equals(type)) {
        if (bigIntCodes.contains(code)) {
          type = "BigInteger";
        }
      }

      String text;

      text = "  public " + type + " ";
      if (clazz == BooleanAttribute.class) {
        text += paramName + "() {" + "\n    Attribute attr = getAttribute(" + name +
            ");\n    return attr == null ? null : " + "((BooleanAttribute) attr).getValue();";
      } else if (clazz == LongAttribute.class || clazz == MechanismAttribute.class) {
        if (type.equals("Long")) {
          text += paramName + "() {" + "\n    Attribute attr = getAttribute(" + name +
              ");\n    return attr == null ? null : " + "((LongAttribute) attr).getValue();";
        } else {
          text += paramName + "() {" + "\n    Attribute attr = getAttribute(" + name +
              ");\n    return attr == null ? null : " + "((LongAttribute) attr).getIntValue();";
        }
      } else if (clazz == CharArrayAttribute.class) {
        text += paramName + "() {" + "\n    Attribute attr = getAttribute(" + name +
            ");\n    return attr == null ? null : " + "((CharArrayAttribute) attr).getValue();";
      } else if (clazz == ByteArrayAttribute.class) {
        if ("byte[]".equals(type)) {
          text += paramName + "() {" + "\n    Attribute attr = getAttribute(" + name +
              ");\n    return attr == null ? null : " + "((ByteArrayAttribute) attr).getValue();";
        } else {
          text += paramName + "() {" + "\n    Attribute attr = getAttribute(" + name +
              ");\n    return attr == null ? null : " + "((ByteArrayAttribute) attr).getBigIntValue();";
        }
      } else if (clazz == DateAttribute.class) {
        text += paramName + "() {" + "\n    Attribute attr = getAttribute(" + name +
            ");\n    return attr == null ? null : " + "((DateAttribute) attr).getValue();";
      } else if (clazz == MechanismArrayAttribute.class) {
        text += paramName + "() {" + "\n    Attribute attr = getAttribute(" + name +
            ");\n    return attr == null ? null : " + "((MechanismArrayAttribute) attr).getValue();";
      } else if (clazz == AttributeArrayAttribute.class) {
        text += paramName + "() {" + "\n    Attribute attr = getAttribute(" + name +
            ");\n    return attr == null ? null : " + "((AttributeArrayAttribute) attr).getValue();";
      } else {
        throw new IllegalStateException("unknown class " + clazz.getName());
      }

      text += "\n  }";
      System.out.println(text);
      System.out.println();

      text = "  public AttributeVector " + paramName + "(" + type + " " + paramName + ") {" +
          "\n    return attr(" + name + ", " + paramName + ");" +
          "\n  }";
      System.out.println(text);
      System.out.println();
    }
  }

}
