# envelope-encryption

**envelope-encryption** is an encryption technique where you encrypt privacy or sensitive data using a unique
key (known as data key) for every word, text or binary data instead of using a single key to encrypt the entire
database. Then, each of the data key will be encrypted remotely using a master key that resides in Key Management
System (KMS) such as Google Cloud. This way, it ensures the safety of your data in the event of data breach because 
attackers would need to compromise every single data key in order to decrypt the encrypted data but only if they also 
able to breach the master key stored in very highly secured KMS provider vault. Therefore, the chances of compromising
data that is encrypted using **envelope-encryption** technique is zero to none.

This is a simple open source SDK api to perform encryption and decryption of text data utilizing the envelope encryption 
technique. In this api the base64 encrypted string would append the encrypted data key string with the encrypted data 
itself in the following format:

> {encrypted_data_key}encrypted_data

Ideally the encrypted data key and encrypted data should be stored separately in different database or schema to ensure
100% safety, so master key, data key, and encrypted data would be stored in 3 different locations.

## Importing envelope-encryption SDK

Once you download the jar file of this release from my GitHub repository and import it into your own repository or 
local .m2 directory, add the following maven dependency in your maven project pom.xml file:

```xml
	<dependency>
		<groupId>com.suryadisoft</groupId>
		<artifactId>envelope-encryption</artifactId>
		<version>1.0.0</version>
	</dependency>
```

### Configuration

You can customize some configuration in this api and if you are using google kms provider, there are some required
configuration that you need to set.

```text
# Cipher Configuration
# the name of the transformation, e. g., AES/ CBC/ PKCS5Padding. See the Cipher section in the Java Security Standard 
# Algorithm Names Specification for information about standard transformation names.
transformation=AES/GCM/NoPadding
# the standard name of the requested key algorithm. See the KeyGenerator section in the Java Security Standard Algorithm 
# Names Specification for information about standard algorithm names.
algorithm=AES
# the name of the algorithm requested. See the MessageDigest section in the Java Security Standard Algorithm Names 
# Specification for information about standard algorithm names.
hashAlgorithm=SHA3-256

# Local KMS configuration (if you maintain your own master key)
# The base64 master key string generated using the CipherUtil#generateNewKey(String)
masterKey=

# Google KMS configuration
# Google Service Account json file to access Google KMS
credentialFile=
# Google Cloud Platform project id
projectId=
# Google KMS key ring location
locationId=
# Google KMS key ring id
keyRingId=
# Google KMS key id
keyId=
```

## Usage Examples

### Instantiates CipherUtil instance

#### Instantiates with local kms and auto-generated master-key for testing purpose only
```java
CipherUtil cipherUtil = CipherUtil.getInstance();
```
#### Instantiates with local kms and predefined master-key inside the properties
```java
Properties properties = new Properties();
properties.setProperty("masterKey", "XYZ");
CipherUtil cipherUtil = CipherUtil.getInstance(properties);
```
#### Instantiates with google kms configuration inside the properties
```java
Properties properties = new Properties();
properties.setProperty("projectId", "myProject");
properties.setProperty("locationId", "us-west2");
properties.setProperty("keyRingId", "keyRing");
properties.setProperty("keyId", "myKey");
properties.setProperty("credentialFile", "myFile.json"); // on classpath
CipherUtil cipherUtil = CipherUtil.getInstance(Type.GOOGLE_KMS, properties);
```

### Encrypting Data
```java
String encryptedText = cipherUtil.encrypt("plaintext");
```

### Decrypting Data
```java
String plainText = cipherUtil.decrypt(encryptedText);
```

### Hashing Data
```java
String hash = cipherUtil.hash("plaintext", CipherUtil.generateNewSalt());
```
