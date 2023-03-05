## Licenses
This product includes software (IAIK PKCS#11 wrapper version 1.6.6) 
developed by Stiftung SIC which is licensed under "IAIK PKCS#11 Wrapper License".
All other parts are licensed under Apache License, version 2.
For details please refer to the file [LICENSE](LICENSE).

## Prerequisite
- JRE / JDK 8 or above

Use xipki/jpkcs11wrapper in your project
=====
- Maven  
  ```
  <dependency>
      <groupId>org.xipki</groupId>
      <artifactId>jpkcs11wrapper</artifactId>
      <version>1.0.2</version>
  </dependency>
  ```
- Or copy the following jar file to your classpath:
  - [jpkcs11wrapper-1.0.0.jar](https://github.com/xipki/jpkcs11wrapper/releases/download/v1.0.0/jpkcs11wrapper-1.0.0.jar)

JDK17 or above
=====
To use pkcs11wrapper in JDK 17 or above, please add the following java option:
```
--add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED
```

JUnit tests
=====
- Configure the library and PIN of your HSM module in the file `src/test/resources/pkcs11.properties`.
- `mvn test`  
   - To activate the speed tests use `-PspeedTests`
   - By default, the speed test will run with 2 threads, you can change the
     value via the Java property `speed.threads`, e.g.
    `-Dspeed.threads=5` to use 5 threads.
   - By default, the speed test will take 3 seconds, you can change the
     value via the Java property `speed.duration`, e.g.
    `-Dspeed.duration=10s` for 10 seconds.
