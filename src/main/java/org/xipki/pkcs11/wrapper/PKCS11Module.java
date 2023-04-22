// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.PKCS11;

import java.io.*;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

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
   * The ECDSA signature is in X9.62 format.
   */
  static final int BEHAVIOUR_ECDSA_SIGNATURE_X962 = 1;

  /**
   * The SM2 signature is in X9.62 format.
   */
  static final int BEHAVIOUR_SM2_SIGNATURE_X962 = 2;

  /**
   * The private key of type CKK_EC has the attribute CKA_EC_POINT.
   */
  static final int BEHAVIOUR_EC_PRIVATEKEY_ECPOINT = 3;

  /**
   * The private key of type CKK_VENDOR_SM2 has the attribute CKA_EC_POINT.
   */
  static final int BEHAVIOUR_SM2_PRIVATEKEY_ECPOINT = 4;

  /**
   * Interface to the underlying PKCS#11 module.
   */
  private PKCS11 pkcs11;

  private final String modulePath;

  private Boolean ecPointFixNeeded;

  private Boolean ecdsaSignatureFixNeeded;

  private Boolean sm2SignatureFixNeeded;

  private Map<PKCS11Constants.Category, VendorMap> vendorMaps;

  private Map<Long, String> ckrCodeNameMap;

  private final Set<Integer> vendorBehaviours = new HashSet<>();

  private static final AtomicBoolean licensePrinted = new AtomicBoolean(false);

  /**
   * Create a new module that uses the given PKCS11 interface to interact with
   * the token.
   *
   * @param modulePath
   *          The interface to interact with the token.
   */
  protected PKCS11Module(String modulePath) {
    this.modulePath = Functions.requireNonNull("modulePath", modulePath);
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
    synchronized (licensePrinted) {
      if (!licensePrinted.get()) {
        StaticLogger.info(
                "This product (ipkcs11wrapper) includes software (IAIK PKCS#11 wrapper version 1.6.8)\n"
                + "developed by Stiftung SIC which is licensed under \"IAIK PKCS#11 Wrapper License\"- \n"
                + "A copy of this license is downloadable under \n"
                + "https://jce.iaik.tugraz.at/products/core-crypto-toolkits/pkcs11-wrapper/#License.\n"
                + "All other parts are licensed under Apache License, version 2.");
        licensePrinted.set(true);
      }
    }

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

  Boolean getEcPointFixNeeded() {
    return ecPointFixNeeded;
  }

  void setEcPointFixNeeded(Boolean ecPointFixNeeded) {
    this.ecPointFixNeeded = ecPointFixNeeded;
  }

  Boolean getEcdsaSignatureFixNeeded() {
    return ecdsaSignatureFixNeeded;
  }

  void setEcdsaSignatureFixNeeded(Boolean ecdsaSignatureFixNeeded) {
    this.ecdsaSignatureFixNeeded = ecdsaSignatureFixNeeded;
  }

  Boolean getSm2SignatureFixNeeded() {
    return sm2SignatureFixNeeded;
  }

  void setSm2SignatureFixNeeded(Boolean sm2SignatureFixNeeded) {
    this.sm2SignatureFixNeeded = sm2SignatureFixNeeded;
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
      throw convertException(ex);
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
    wrapperInitArgs.flags |= PKCS11Constants.CKF_OS_LOCKING_OK;

    final String functionList = "C_GetFunctionList";
    final boolean omitInitialize = false;
    StaticLogger.info("C_Initialize: modulePath={}, flags=0x{}", modulePath,
        Functions.toFullHex(wrapperInitArgs.flags));
    try {
      pkcs11 = PKCS11.getInstance(modulePath, functionList, wrapperInitArgs, omitInitialize);
    } catch (IOException ex) {
      throw new TokenException(ex.getMessage(), ex);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw convertException(ex);
    } catch (NoSuchMethodError ex) {
      // In some JDKs like red hat, the getInstance is extended by fipsKeyImporter as follows:
      // getInstance(String pkcs11ModulePath, String functionList, CK_C_INITIALIZE_ARGS pInitArgs,
      //    boolean omitInitialize, MethodHandle fipsKeyImporter)
      try {
        Method getInstanceMethod = PKCS11.class.getMethod("getInstance",
            String.class, String.class, CK_C_INITIALIZE_ARGS.class, boolean.class, MethodHandle.class);
        pkcs11 = (PKCS11) getInstanceMethod.invoke(null, modulePath, functionList,
            wrapperInitArgs, omitInitialize, null);
      } catch (Exception ex1) {
        throw new TokenException(ex1.getMessage(), ex1);
      }
    }

    initVendor();
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
      throw convertException(ex);
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

  boolean hasVendorBehaviour(int vendorBehavior) {
    return vendorBehaviours.contains(vendorBehavior);
  }

  public long genericToVendor(PKCS11Constants.Category category, long genericCode) {
    if (vendorMaps != null) {
      VendorMap map = vendorMaps.get(category);
      return map != null ? map.genericToVendor(genericCode) : genericCode;
    } else {
      return genericCode;
    }
  }

  public long vendorToGeneric(PKCS11Constants.Category category, long vendorCode) {
    if (vendorMaps != null) {
      VendorMap map = vendorMaps.get(category);
      return map != null ? map.vendorToGeneric(vendorCode) : vendorCode;
    } else {
      return vendorCode;
    }
  }

  public String codeToName(PKCS11Constants.Category category, long code) {
    if (vendorMaps != null) {
      VendorMap map = vendorMaps.get(category);
      return map != null ? map.codeToName(code) : PKCS11Constants.codeToName(category, code);
    } else {
      return PKCS11Constants.codeToName(category, code);
    }
  }

  public Long nameToCode(PKCS11Constants.Category category, String name) {
    if (vendorMaps != null) {
      VendorMap map = vendorMaps.get(category);
      return map != null ? map.nameToCode(name) : PKCS11Constants.nameToCode(category, name);
    } else {
      return PKCS11Constants.nameToCode(category, name);
    }
  }

  String ckrCodeToName(long code) {
    String name = ckrCodeNameMap != null ? ckrCodeNameMap.get(code) : null;
    return name != null ? name : PKCS11Constants.ckrCodeToName(code);
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

  public PKCS11Exception convertException(sun.security.pkcs11.wrapper.PKCS11Exception e) {
    String name = ckrCodeToName(e.getErrorCode());
    return new PKCS11Exception(e.getErrorCode(), name);
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
      throw convertException(ex);
    }
  }

  private void assertInitialized() {
    if (pkcs11 == null) {
      throw new IllegalStateException("Module not initialized yet, please call initialize() first");
    }
  }

  private void initVendor() {
    try {
      ModuleInfo moduleInfo = getInfo();
      String manufacturerID = moduleInfo.getManufacturerID();
      String libraryDescription = moduleInfo.getLibraryDescription();
      Version libraryVersion = moduleInfo.getLibraryVersion();

      String confPath = System.getProperty("org.xipki.pkcs11.vendor.conf");
      InputStream in = (confPath != null) ? Files.newInputStream(Paths.get(pkcs11ModulePath))
          : PKCS11Module.class.getClassLoader().getResourceAsStream("org/xipki/pkcs11/wrapper/vendor.conf");

      try (BufferedReader br = new BufferedReader(new InputStreamReader(in))) {
        while (true) {
          VendorConfBlock block = readVendorBlock(br);
          if (block == null) {
            break;
          }

          if (!block.matches(modulePath, manufacturerID, libraryDescription, libraryVersion)) {
            continue;
          }

          StaticLogger.info("found <vendor> configuration: {}", block);
          // vendor behaviours
          if (block.vendorBehaviours != null) {
            StringTokenizer tokenizer = new StringTokenizer(block.vendorBehaviours, ":, \t");
            while (tokenizer.hasMoreTokens()) {
              String token = tokenizer.nextToken();
              if ("SM2_SIGNATURE_X962".equalsIgnoreCase(token)) {
                vendorBehaviours.add(BEHAVIOUR_SM2_SIGNATURE_X962);
              } else if ("ECDSA_SIGNATURE_X962".equalsIgnoreCase(token)) {
                vendorBehaviours.add(BEHAVIOUR_ECDSA_SIGNATURE_X962);
              } else if ("SM2_PRIVATEKEY_ECPOINT".equalsIgnoreCase(token)) {
                vendorBehaviours.add(BEHAVIOUR_SM2_PRIVATEKEY_ECPOINT);
              } else if ("EC_PRIVATEKEY_ECPOINT".equalsIgnoreCase(token)) {
                vendorBehaviours.add(BEHAVIOUR_EC_PRIVATEKEY_ECPOINT);
              } else {
                StaticLogger.warn("Ignored unknown vendor behaviour '" + token + "'.");
              }
            }
          }

          VendorMap ckdMap = new VendorMap(PKCS11Constants.Category.CKD);
          VendorMap ckgMap = new VendorMap(PKCS11Constants.Category.CKG_MGF);
          VendorMap ckkMap = new VendorMap(PKCS11Constants.Category.CKK);
          VendorMap ckmMap = new VendorMap(PKCS11Constants.Category.CKM);

          for (Map.Entry<String, String> entry : block.nameToCodeMap.entrySet()) {
            String name = entry.getKey().toUpperCase(Locale.ROOT);
            String code = entry.getValue().toUpperCase(Locale.ROOT);
            if (name.startsWith("CKD_")) {
              ckdMap.addNameCode(name, code);
            } else if (name.startsWith("CKG_")) {
              ckgMap.addNameCode(name, code);
            } else if (name.startsWith("CKK_")) {
              ckkMap.addNameCode(name, code);
            } else if (name.startsWith("CKM_")) {
              ckmMap.addNameCode(name, code);
            } else if (name.startsWith("CKR_")) {
              if (ckrCodeNameMap == null) {
                ckrCodeNameMap = new HashMap<>();
              }
              ckrCodeNameMap.put(parseCode(code), name);
            } else {
              throw new IllegalStateException("Unknown name in vendor block: " + name);
            }
          } // end for

          VendorMap[] maps = {ckdMap, ckgMap, ckkMap, ckmMap};
          for (VendorMap map : maps) {
            if (vendorMaps == null) {
              vendorMaps = new HashMap<>();
            }
            vendorMaps.put(map.category, map);
          }

          break;
        } // end while
      }
    } catch (Exception e) {
      StaticLogger.warn("error reading VENDOR code mapping, ignore it.");
    }
  }

  private static VendorConfBlock readVendorBlock(BufferedReader reader) throws IOException {
    boolean inBlock = false;
    String line;
    VendorConfBlock block = null;
    while ((line = reader.readLine()) != null) {
      line = line.trim();
      if (line.isEmpty() || line.charAt(0) == '#') {
        continue;
      }

      if (line.startsWith("<vendor>")) {
        block = new VendorConfBlock();
        inBlock = true;
      } else if (line.startsWith("</vendor>")) {
        block.validate();
        return block;
      } else if (inBlock) {
        if (line.startsWith("module.")) {
          int idx = line.indexOf(' ');
          if (idx == -1) {
            continue;
          }

          String value = line.substring(idx + 1).trim();
          if (value.isEmpty()) {
            continue;
          }

          String name = line.substring(0, idx).trim();
          List<String> textList = Arrays.asList(value.toLowerCase(Locale.ROOT).split(":"));
          if (name.equalsIgnoreCase("module.path")) {
            block.modulePaths = textList;
          } else if (name.equalsIgnoreCase("module.mid")) {
            block.manufacturerIDs = textList;
          } else if (name.equalsIgnoreCase("module.description")) {
            block.descriptions = textList;
          } else if (name.equalsIgnoreCase("module.version")) {
            block.versions = textList;
          }
        } else if (line.startsWith("CKD_") || line.startsWith("CKG_") ||
            line.startsWith("CKK_") || line.startsWith("CKM_") || line.startsWith("CKR_")) {
          int idx = line.indexOf(' ');
          if (idx != -1) {
            block.nameToCodeMap.put(line.substring(0, idx).trim(), line.substring(idx + 1).trim());
          }
        } else if (line.startsWith("VENDOR_BEHAVIORS ")) {
          int idx = line.indexOf(' ');
          String value = line.substring(idx + 1).trim();
          if (!value.isEmpty()) {
            block.vendorBehaviours = value;
          }
        }
      }
    }

    return block;
  }

  private static long parseCode(String str) {
    boolean hex = str.startsWith("0X");
    return hex ? Long.parseLong(str.substring(2), 16) : Long.parseLong(str);
  }

  private static final class VendorMap {

    private final Map<Long, Long> genericToVendorMap = new HashMap<>();

    private final Map<Long, Long> vendorToGenericMap = new HashMap<>();

    private final Map<Long, String> codeNameMap      = new HashMap<>();

    private final Map<String, Long> nameCodeMap      = new HashMap<>();

    private PKCS11Constants.Category category;

    VendorMap(PKCS11Constants.Category category) {
      this.category = category;
    }

    void addNameCode(String name, String code) {
      long lCode = parseCode(code);
      Long genericCode = PKCS11Constants.nameToCode(category, name);
      if (genericCode == null) {
        codeNameMap.put(lCode, name);
        nameCodeMap.put(name, lCode);
      } else {
        genericToVendorMap.put(genericCode, lCode);
        vendorToGenericMap.put(lCode, genericCode);
      }
    }

    boolean isEmpty() {
      return genericToVendorMap.isEmpty() && codeNameMap.isEmpty();
    }

    long genericToVendor(long genericCode) {
      return genericToVendorMap.getOrDefault(genericCode, genericCode);
    }

    long vendorToGeneric(long vendorCode) {
      return vendorToGenericMap.getOrDefault(vendorCode, vendorCode);
    }

    public String codeToName(long code) {
      return codeNameMap.get(code);
    }

    public Long nameToCode(String name) {
      return nameCodeMap.get(name);
    }

  }

  private static final class VendorConfBlock {
    private List<String> modulePaths;
    private List<String> manufacturerIDs;
    private List<String> descriptions;
    private List<String> versions;
    private String vendorBehaviours;
    private final Map<String, String> nameToCodeMap = new HashMap<>();

    void validate() throws IOException {
      if (isEmpty(modulePaths) && isEmpty(manufacturerIDs) && isEmpty(descriptions)) {
        throw new IOException("invalid <vendor>-block");
      }
    }

    boolean matches(String modulePath, String manufacturerID, String libraryDescription, Version libraryVersion) {
      if ((!isEmpty(modulePaths)     && !contains(modulePaths,     Paths.get(modulePath).getFileName().toString())) ||
          (!isEmpty(manufacturerIDs) && !contains(manufacturerIDs, manufacturerID)) ||
          (!isEmpty(descriptions)    && !contains(descriptions,    libraryDescription))) {
        return false;
      }

      if (isEmpty(versions)) {
        return true;
      }

      int iVersion = ((0xFF & libraryVersion.getMajor()) << 8) + (0xFF & libraryVersion.getMinor());
      boolean match = false;
      for (String t : versions) {
        int idx = t.indexOf("-");
        int from = (idx == -1) ? toIntVersion(t) : toIntVersion(t.substring(0, idx));
        int to   = (idx == -1) ? from            : toIntVersion(t.substring(idx + 1));

        if (iVersion >= from && iVersion <= to) {
          match = true;
          break;
        }
      }

      return match;
    }

    private static int toIntVersion(String version) {
      StringTokenizer st = new StringTokenizer(version, ".");
      return (Integer.parseInt(st.nextToken()) << 8) + Integer.parseInt(st.nextToken());
    }

    private static boolean isEmpty(Collection<?> c) {
      return c == null || c.isEmpty();
    }

    private static boolean contains(List<String> list, String str) {
      str = str.toLowerCase(Locale.ROOT);
      for (String s : list) {
        if (str.contains(s)) {
          return true;
        }
      }
      return false;
    }

    @Override
    public String toString() {
      return "VendorConfBlock" +
          "\n  modulePaths:      " + modulePaths +
          "\n  manufacturerIDs:  " + manufacturerIDs +
          "\n  descriptions:     " + descriptions +
          "\n  versions:         " + versions +
          "\n  vendorBehaviours: " + vendorBehaviours +
          "\n  nameToCodeMap:    " + nameToCodeMap;
    }

  } // class VendorConfBlock

}
