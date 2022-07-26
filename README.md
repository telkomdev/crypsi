## crypsi (Node Crypto Utility)

Custom crypto utility that wraps the `crypto` node module to make life easier

[![crypsi Node CI](https://github.com/telkomdev/crypsi/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/telkomdev/crypsi/actions/workflows/ci.yml)

### Install
```shell
$ npm i crypsi
```

### Usage

Just open the `unit test` folder, all available there.


#### Example Generate RSA Private and Public Key

```javascript
const { rsa, keyUtil } = require('crypsi');
const fs = require('fs');

rsa.generateRSAkeyPair(keyUtil.KEY_SIZE_4KB, '').then(pairs => {
    console.log(pairs.publicKey);
    console.log(pairs.privateKey);

    const publicKeyWriter = fs.createWriteStream('public.key');
    publicKeyWriter.write(pairs.publicKey);
    
    const privateKeyWriter = fs.createWriteStream('private.key');
    privateKeyWriter.write(pairs.privateKey);

    publicKeyWriter.close();
    privateKeyWriter.close();
}).catch(err => {
    console.log(err);
});
```

Result RSA Public Key
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwIrVMXSXC5vxh+0fJny0
5neOzrb3kqvGOzLBgza4Emxj+MRLqzn1MtcSFobjwqlWoof8/5ycV0L74fhOywcX
n61vHwik/8As0HkyWK8yRd98T1Q5Z8U+ZYrl959h96Bi6il6y4IN+t7A8lfV2Rvz
UMEl9agfg0xNqPhEUFHCyDYzM7dW9cmSHyUhl+rp9RA/udNkv/k4ak7C4YmQEZyg
b9uEVlFY5Bpod5rZGm6roWqwZ54neDREuI4E7fWTnDXbYqif6/lNcBDvKW9s5oqx
YecNjMsrNrXQHkndoFENouzirQSITbxmwMAE5sJsU0RcFFP0yjsMtfSPSN48ubFH
mQIDAQAB
-----END PUBLIC KEY-----
```

Result RSA Private Key

```
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDAitUxdJcLm/GH
7R8mfLTmd47OtveSq8Y7MsGDNrgSbGP4xEurOfUy1xIWhuPCqVaih/z/nJxXQvvh
+E7LBxefrW8fCKT/wCzQeTJYrzJF33xPVDlnxT5liuX3n2H3oGLqKXrLgg363sDy
V9XZG/NQwSX1qB+DTE2o+ERQUcLINjMzt1b1yZIfJSGX6un1ED+502S/+ThqTsLh
iZARnKBv24RWUVjkGmh3mtkabquharBnnid4NES4jgTt9ZOcNdtiqJ/r+U1wEO8p
b2zmirFh5w2Myys2tdAeSd2gUQ2i7OKtBIhNvGbAwATmwmxTRFwUU/TKOwy19I9I
3jy5sUeZAgMBAAECggEASf0Pr9F9uZhTWEhmkAOcAHQxDH6C5Hnd0yHN+v4r/ehp
Ak9sRIAhGUhMSxvKqiMoh4x6TD+CVIYJBOzGWn5/NX0QFnzb6uuOTQ5Fqo6oYvFe
c52J8bZ6I8scU+uLWfzoBdOqvEld1emDe50FMEjtVzrhu2S/t1S7AxNkLPk+QHDo
uw4tx7C1Vfq1qLXSo2ShaR1aKgS14m5HjIX6tqgic4IQPKVCv2PArsSBNp9mXD+x
kNnKKfwlZERqXV9eC70CFbU3liPxcRLF/kBuR1Gk1F2cXuSb5bEJ1lDnc1I2vJcd
Ux8yI81Ps/kOM+YXfJgrmQ/2Wp1/5NoZBCFgNwFQAQKBgQDmm/7VuXh5IVUimtMa
IYMJIkRl6hevsM785OkO/lfw/hV3MLoWe1F4qQwfAODTrsr2zEOjioyhzvT+53aa
O9TDIp0Suguv/dZOE388PxfrcB8mfTiYwGVn7JkINXyZap3MQLvznpVnLYYnETNI
AusAf/xXdSMt9v3qUbnA5aNhMQKBgQDVvd8fwLk4JqKpup4zwhMupTuwXdyn4SRE
QCYfhhC1q02oUkMEO4EMPmc0dPQDlI4E564qHG6OFwm/vtWL96//qdn5ExJLlfe2
DmQwk0gJivc5ZMmZMD8CTgtJLRcJDOe1YjwqnEqU3kcuX5lvbXczZOVIU0PW6kmd
LTJtRJZy6QKBgCu8/pJuwQjIZ6tOjidwn7fFxg9GXQO3lyqkCAgN+YP9zPh0R3co
IIWwGlpvAjVj+57fkxyblJzD8fe+0uHh4zK3h+8bVkgk7taUIBe/J7xB4cadDXT7
WMBjQYsrCdzXOeKZjIxiUZfmLIGQY5eO5h+MJsI3t1pqdDJTGdYaN+ihAoGAcrj+
0aQ3xhO2qzMnRtCcSyUU7Iz0qocFWDy2OaVTwq63d+jvX44wrcmwy08ayfEqaSeR
K7km/c0PxoM/S2keZjNcc3vxDfDojCcdT5U9zSFxoLSgIEDtEOei1xwEiS8MDycy
9Av/W/gSbKmTSWOP314AUtmeR/RonpxrvIpb1kECgYAiRqS7MDwPVsktnzuT9ZWx
HDfktrdWAHO5+S2zG9gbCOgnhiOyIq4GakHgbdVlj2xsisOMGULFXEJBP3v8SzgF
7V2kM7+ThdnmQJaQC561871hb9gh5hOkf/GO9Gxe0cBOF4HmHO+QiQvylLdx/w8X
n3LQsISpln3R7g8riWFeWg==
-----END PRIVATE KEY-----
```

#### Example Loading RSA Private and Public Key
```javascript
const { rsa } = require('crypsi');
const fs = require('fs');

// loading RSA private key from file
const privateKeyData = fs.readFileSync('./testdata/private.key');
const privateKey = rsa.loadPrivateKey(privateKeyData);

console.log(privateKey);

// loading RSA public key from file
const publicKeyData = fs.readFileSync('./testdata/public.key');
const publicKey = rsa.loadPublicKey(publicKeyData);

console.log(publicKey);
```

#### Example Loading RSA Private and Public Key as Base64 String
```javascript
const { rsa } = require('crypsi');
const fs = require('fs');

// loading RSA private key from file
const privateKeyData = fs.readFileSync('./testdata/private.key');
const privateKeyBase64 = rsa.loadPrivateKeyAsBase64(privateKeyData);

console.log(privateKeyBase64);

// loading RSA public key from file
const publicKeyData = fs.readFileSync('./testdata/public.key');
const publicKeyBase64 = rsa.loadPublicKeyAsBase64(publicKeyData);

console.log(publicKeyBase64);
```

#### Example Loading RSA Private and Public Key as Base64 String and load back as RSA private and public key
```javascript
const { rsa } = require('crypsi');
const fs = require('fs');

// loading RSA private key from file
const privateKeyData = fs.readFileSync('./testdata/private.key');
const privateKeyBase64 = rsa.loadPrivateKeyAsBase64(privateKeyData);

// for example: save privateKeyBase64 to database
const privateKey = rsa.loadPrivateKeyFromBase64(privateKeyBase64);
console.log(privateKey);

// loading RSA public key from file
const publicKeyData = fs.readFileSync('./testdata/public.key');
const publicKeyBase64 = rsa.loadPublicKeyAsBase64(publicKeyData);

// for example: save publicKeyBase64 to database

const publicKey = rsa.loadPublicKeyFromBase64(publicKeyBase64);
console.log(publicKey);
```

#### Example Digital Signature with RSA Private and Public Key

```javascript
const { rsa, rsaSign, keyUtil } = require('crypsi');
const { Buffer } = require('buffer');
const fs = require('fs');

rsa.generateRSAkeyPair(keyUtil.KEY_SIZE_4KB, '').then(pairs => {
    console.log(pairs.publicKey);
    console.log(pairs.privateKey);

    // data can be anything, from simple string or Buffer of file
    const fileData = fs.readFileSync('./testdata/myfile.txt');

    // sign with private key
    const signature = rsaSign.signWithSha256(pairs.privateKey, Buffer.from(fileData));

     // => for example: save signature to database

    // verifying digital signature with public key
    const signatureValid = rsaSign.verifyWithSha256(pairs.publicKey, signature, Buffer.from(fileData));
    console.log(signatureValid);
}).catch(err => {
    console.log(err);
});
```

#### Example Encryption with RSA Private and Public Key
```javascript
const { rsa, rsaEncryption, keyUtil } = require('crypsi');
const fs = require('fs');

rsa.generateRSAkeyPair(keyUtil.KEY_SIZE_4KB, '').then(pairs => {
    console.log(pairs.publicKey);
    console.log(pairs.privateKey);

    // data can be anything, from simple string or Buffer of file
    const fileData = fs.readFileSync('./testdata/myfile.txt');

    // encrypt with public key
    const encryptedData = rsaEncryption.encryptWithOaepSha256(pairs.publicKey, fileData);

    // decrypt with private key
    const decryptedData = rsaEncryption.decryptWithOaepSha256(pairs.privateKey, encryptedData);

    console.log(decryptedData);
}).catch(err => {
    console.log(err);
});
```

#### Example Generate Hash with common Digest Algorithm
```javascript
const { digest } = require('crypsi');

const data = 'hello world';

// MD5
const generatedHashMd5 = digest.md5(data);
console.log(generatedHashMd5);

// SHA1
const generatedHashSha1 = digest.sha1(data);
console.log(generatedHashSha1);

// SHA256
const generatedHashSha256 = digest.sha256(data);
console.log(generatedHashSha256);

// SHA384
const generatedHashSha384 = digest.sha384(data);
console.log(generatedHashSha384);

// SHA384
const generatedHashSha512 = digest.sha512(data);
console.log(generatedHashSha512);
```

#### Example Generate Hash with HMAC
Keyed-Hash Message Authentication Code (HMAC) as defined in U.S. Federal Information Processing Standards Publication 198. An HMAC is a cryptographic hash that uses a key to sign a message (from Golang Documentation).
```javascript
const { hmac } = require('crypsi');

const key = 'abc$#128djdyAgbjau&YAnmcbagryt5x';
const data = 'hello world';

// MD5
const generatedHmacMd5 = hmac.md5(key, data);
console.log(generatedHmacMd5);

// SHA1
const generatedHmacSha1 = hmac.sha1(key, data);
console.log(generatedHmacSha1);

// SHA256
const generatedHmacSha256 = hmac.sha256(key, data);
console.log(generatedHmacSha256);

// SHA384
const generatedHmacSha384 = hmac.sha384(key, data);
console.log(generatedHmacSha384);

// SHA384
const generatedHmacSha512 = hmac.sha512(key, data);
console.log(generatedHmacSha512);
```

#### Example Encryption with AES Algorithm
Expected key len:
- AES 128: key length should be 16 bytes
- AES 192: key length should be 24 bytes
- AES 256: key length should be 32 bytes

Data encryption with `AES 256 CBC`
```javascript
const { aesEncryption } = require('crypsi');

const key = 'abc$#128djdyAgbjau&YAnmcbagryt5x';
const data = 'hello world';

// encrypt data with AES 256 CBC
const encryptedData = aesEncryption.encryptWithAes256Cbc(key, data);
console.log(encryptedData);

// decrypt data with AES 256 CBC with the same key
const decryptedData = aesEncryption.decryptWithAes256Cbc(key, encryptedData);
console.log(decryptedData);
```