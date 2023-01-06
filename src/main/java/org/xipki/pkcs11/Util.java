/*
 *
 * Copyright (c) 2022 - 2023 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.pkcs11;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * A class consisting of static methods only which provide certain static
 * pieces of code that are used frequently in this project.
 *
 * @author Lijun Liao
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

}
