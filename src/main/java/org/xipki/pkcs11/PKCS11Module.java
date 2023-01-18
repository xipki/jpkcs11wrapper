// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11;

import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.PKCS11;

import java.io.File;
import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Method;

import static org.xipki.pkcs11.PKCS11Constants.CKF_OS_LOCKING_OK;

/**
 * <B>Caution:
 * Unlike the original IAIK PKCS#11 wrapper, we only call initialize() once per
 * native .so/.dll. Once finalize(Object) has been called, the module cannot
 * be initialized anymore.
 * </B>
 * <p>
 * Objects of this class represent a PKCS#11 module. The application should
 * create an instance by calling getInstance and passing the name of the
 * PKCS#11 module of the desired token; e.g. "slbck.dll". The application
 * must give the full path of the PKCS#11 module unless the module is in the
 * system's search path or in the path of the java.library.path system
 * property.
 * <p>
 * According to the specification, the application must call the initialize
 * method before calling any other method of the module.
 * This class contains slot and token management functions as defined by the
 * PKCS#11 standard.
 *
 * All applications using this library will contain the following code.
 * <pre><code>
 *      PKCS11Module pkcs11Module = PKCS11Module.getInstance("cryptoki.dll");
 *      pkcs11Module.initialize();
 *
 *      // ... work with the module
 *
 *      pkcs11Module.finalize(null);
 * </code></pre>
 * Instead of <code>cryptoki.dll</code>, the application will use the name of
 * the PKCS#11 module of the installed crypto hardware.
 * After the application initialized the module, it can get a list of all
 * available slots. A slot is an object that represents a physical or logical
 * device that can accept a cryptographic token; for instance, the card slot of
 * a smart card reader. The application can call
 * <pre><code>
 * Slot[] slots = pkcs11Module.getSlotList(false);
 * </code></pre>
 * to get a list of all available slots or
 * <pre><code>
 * Slot[] slotsWithToken = pkcs11Module.getSlotList(true);
 * </code></pre>
 * to get a list of all those slots in which there is a currently a token
 * present.
 * <p>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */

public class PKCS11Module {

  /**
   * Interface to the underlying PKCS#11 module.
   */
  private PKCS11 pkcs11;

  private final String pkcs11ModulePath;

  private VendorCode vendorCode;

  private final ModuleFix moduleFix = new ModuleFix();

  /**
   * Create a new module that uses the given PKCS11 interface to interact with
   * the token.
   *
   * @param pkcs11ModulePath
   *          The interface to interact with the token.
   */
  protected PKCS11Module(String pkcs11ModulePath) {
    this.pkcs11ModulePath = Functions.requireNonNull("pkcs11ModulePath", pkcs11ModulePath);
  }

  /**
   * Get an instance of this class by giving the name of the PKCS#11 module; e.g. "slbck.dll". Tries
   * to load the PKCS#11 wrapper native library from the class path (jar file) or library path.
   *
   * @param pkcs11ModulePath
   *          The path of the module; e.g. "/path/to/slbck.dll".
   * @return An instance of Module that is connected to the given PKCS#11 module.
   * @exception IOException
   *              If connecting to the named module fails.
   */
  public static PKCS11Module getInstance(String pkcs11ModulePath) throws IOException {
    Functions.requireNonNull("pkcs11ModulePath", pkcs11ModulePath);
    File file = new File(pkcs11ModulePath);
    if (!file.exists()) {
      throw new IOException("File " + pkcs11ModulePath + " does not exist");
    }

    if (!file.isFile()) {
      throw new IOException(pkcs11ModulePath + " is not a file");
    }

    if (!file.canRead()) {
      throw new IOException("Can not read file " + pkcs11ModulePath + "");
    }

    return new PKCS11Module(pkcs11ModulePath);
  }

  ModuleFix getModuleFix() {
    return moduleFix;
  }

  public VendorCode getVendorCode() {
    return vendorCode;
  }

  public void setVendorCode(VendorCode vendorCode) {
    this.vendorCode = vendorCode;
  }

  /**
   * Gets information about the module; i.e. the PKCS#11 module behind.
   *
   * @return An object holding information about the module.
   * @exception PKCS11Exception
   *              If getting the information fails.
   */
  public ModuleInfo getInfo() throws PKCS11Exception {
    assertInitialized();
    try {
      return new ModuleInfo(pkcs11.C_GetInfo());
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex.getErrorCode());
    }
  }

  /**
   * Initializes the module. The application must call this method before
   * calling any other method of the module.
   *
   * @exception PKCS11Exception
   *              If initialization fails.
   */
  public void initialize() throws TokenException {
    CK_C_INITIALIZE_ARGS wrapperInitArgs = new CK_C_INITIALIZE_ARGS();
    wrapperInitArgs.flags |= CKF_OS_LOCKING_OK;

    final String functionList = "C_GetFunctionList";
    final boolean omitInitialize = false;
    try {
      pkcs11 = PKCS11.getInstance(pkcs11ModulePath, functionList, wrapperInitArgs, omitInitialize);
    } catch (IOException ex) {
      throw new TokenException(ex.getMessage(), ex);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex.getErrorCode());
    } catch (NoSuchMethodError ex) {
      // In some JDKs like red hat, the getInstance is extended by fipsKeyImporter as follows:
      // getInstance(String pkcs11ModulePath, String functionList, CK_C_INITIALIZE_ARGS pInitArgs,
      //    boolean omitInitialize, MethodHandle fipsKeyImporter)
      try {
        Method getInstanceMethod = PKCS11.class.getMethod("getInstance",
            String.class, String.class, CK_C_INITIALIZE_ARGS.class, boolean.class, MethodHandle.class);
        pkcs11 = (PKCS11) getInstanceMethod.invoke(null, pkcs11ModulePath, functionList,
            wrapperInitArgs, omitInitialize, null);
      } catch (Exception ex1) {
        throw new TokenException(ex1.getMessage(), ex1);
      }
    }

    ModuleInfo moduleInfo = getInfo();
    try {
      vendorCode = VendorCode.getVendorCode(pkcs11ModulePath, moduleInfo.getManufacturerID(),
          moduleInfo.getLibraryDescription(), moduleInfo.getLibraryVersion());
    } catch (IOException e) {
      System.err.println("Error loading vendorcode: " + e.getMessage());
    }
  }

  /**
   * Gets a list of slots that can accept tokens that are compatible with this
   * module; e.g. a list of PC/SC smart card readers. The parameter determines
   * if the method returns all compatible slots or only those in which there
   * is a compatible token present.
   *
   * @param tokenPresent
   *          Whether only slots with present token are returned.
   * @return An array of Slot objects, may be an empty array but not null.
   * @exception PKCS11Exception
   *              If error occurred.
   */
  public Slot[] getSlotList(boolean tokenPresent) throws PKCS11Exception {
    assertInitialized();
    long[] slotIDs;
    try {
      slotIDs = pkcs11.C_GetSlotList(tokenPresent);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex.getErrorCode());
    }
    Slot[] slots = new Slot[slotIDs.length];
    for (int i = 0; i < slots.length; i++) {
      slots[i] = new Slot(this, slotIDs[i]);
    }

    return slots;
  }

  /*
   * Waits for a slot event. That can be that a token was inserted or
   * removed. It returns the Slot for which an event occurred. The dontBlock
   * parameter can have the value false (BLOCK) or true (DONT_BLOCK).
   * If there is no event present and the method is called with true this
   * method throws an exception with the error code CKR_NO_EVENT (0x00000008).
   *
   * @param dontBlock
   *          Can false (BLOCK) or true (DONT_BLOCK).
   * @return The slot for which an event occurred.
   * @exception PKCS11Exception
   *              If the method was called with WaitingBehavior.DONT_BLOCK but
   *              there was no event available, or if an error occurred.
   *
  public Slot waitForSlotEvent(boolean dontBlock) throws PKCS11Exception {
    return new Slot(this, pkcs11.C_WaitForSlotEvent(dontBlock ? CKF_DONT_BLOCK : 0L, null));
  }
  */

  /**
   * Gets the PKCS#11 module of the wrapper package behind this object.
   *
   * @return The PKCS#11 module behind this object.
   */
  public PKCS11 getPKCS11() {
    assertInitialized();
    return pkcs11;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return The string representation of object
   */
  @Override
  public String toString() {
    return (pkcs11 != null) ? pkcs11.toString() : "null";
  }

  /**
   * <B>Caution:
   * Unlike the original PKCS#11 wrapper, we only call initialize() once per
   * native .so/.dll. Once finalize(Object) has been called, the module cannot
   * be initialized anymore.
   * </B>
   * <p>
   * Finalizes this module. The application should call this method when it
   * finished using the module.
   * Note that this method is different from the <code>finalize</code> method,
   * which is the reserved Java method called by the garbage collector.
   * This method calls the <code>C_Finalize(PKCS11Object)</code> method of the
   * underlying PKCS11 module.
   *
   * @param args
   *          Must be null in version 2.x of PKCS#11.
   * @exception PKCS11Exception
   *              If finalization fails.
   */
  public void finalize(Object args) throws PKCS11Exception {
    try {
      pkcs11.C_Finalize(args);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex.getErrorCode());
    }
  }

  private void assertInitialized() {
    if (pkcs11 == null) {
      throw new IllegalStateException("Module not initialized yet, please call initialize() first");
    }
  }

}
