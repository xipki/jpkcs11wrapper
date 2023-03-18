# Change Log

See also <https://github.com/xipki/jpkcs11wrapper/releases>

## 1.0.4
- Release date: 2023/xx/xx
- N/A

## 1.0.3
- Release date: 2023/03/18
- Session.java: log operations.
- Corrected vendor behaviour of the TASS HSM
- Add KCS11Token to wrap Session. Using this class the application do
  not need to manage (login, logout, open session, etc.) the sessions.

## 1.0.2
- Release date: 2023/03/05
- Add mechanism to log warn/error messages.
- Session.java: add method getDefaultAttrValues() to get all default attribute values of an object.
- session.java: add method findObjectsSingle, signSingle, verifySingle, encryptSingle, decryptSingle, etc.

## 1.0.1
- Release date: 202/2/27
- Better vendor behaviour.
- CKA_EC_POINT: Applicatio do not to handle the ASN.1 envelope.
- AttributeVector: better toString
- Session.findObjects: ignore NULL attributes.

## 1.0.0
- Release date: 2023/02/05 
- First release version of jpkcs11wrapper
