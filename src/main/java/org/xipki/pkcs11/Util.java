// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11;

import sun.security.pkcs11.wrapper.CK_MECHANISM;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * A class consisting of static methods only which provide certain static
 * pieces of code that are used frequently in this project.
 *
 * @author Lijun Liao (xipki)
 */
public class Util {

  public static Class<?> getClass(String className) {
    try {
      return Class.forName(className);
    } catch (Throwable th) {
      return null;
    }
  }

  public static Field getField(Class<?> clazz, String fieldName) {
    try {
      return clazz.getField(fieldName);
    } catch (Throwable th) {
      return null;
    }
  }

  public static Method getMethod(Class<?> clazz, String name, Class<?>... parameterTypes) {
    try {
      return clazz.getMethod(name, parameterTypes);
    } catch (Throwable th) {
      return null;
    }
  }

  public static Constructor<?> getConstructor(String className, Class<?>... parameterTypes) {
    try {
      return getConstructor(Class.forName(className, false, Util.class.getClassLoader()), parameterTypes);
    } catch (Throwable th) {
      return null;
    }
  }

  public static Constructor<?> getConstructor(Class<?> clazz, Class<?>... parameterTypes) {
    try {
      return clazz.getConstructor(parameterTypes);
    } catch (Throwable th) {
      return null;
    }
  }

  public static Constructor<?> getConstructorOfCK_MECHANISM(String paramsClassName) {
    Class<?> paramsClass;
    try {
      paramsClass = Class.forName(paramsClassName);
    } catch (ClassNotFoundException ex) {
      return null;
    }

    return getConstructor(CK_MECHANISM.class, long.class, paramsClass);
  }

}
