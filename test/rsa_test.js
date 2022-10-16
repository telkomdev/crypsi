const assert = require('assert');
const { Buffer } = require('buffer');
const fs = require('fs');
const { rsa, keyUtil } = require('../index');

describe('Test Generate RSA private and public key', () => {
  it('should return non null private and public key', () => {
    rsa.generateRSAKeyPair(keyUtil.KEY_SIZE_4KB, '').then((pairs) => {
      assert.notEqual(pairs, null);
    }).catch((err) => {
      assert.equal(err, null);
    });
  });

  it('should return non null private and public key as base64 format', () => {
    rsa.generateRSAKeyPair(keyUtil.KEY_SIZE_4KB, '').then((pairs) => {

      const privateKeyBase64 = rsa.loadPrivateKeyAsBase64(pairs.privateKey);
      const publicKeyBase64 = rsa.loadPublicKeyAsBase64(pairs.publicKey);
      
      console.log(rsa.loadPrivateKeyFromBase64(privateKeyBase64));
      console.log();
      console.log(rsa.loadPublicKeyFromBase64(publicKeyBase64));

      assert.notEqual(privateKeyBase64, null);
      assert.notEqual(publicKeyBase64, null);
    }).catch((err) => {
      assert.equal(err, null);
    });
  });

  it('should return non null private and public key using aes-256-cbc', () => {
    rsa.generateRSAKeyPair(keyUtil.KEY_SIZE_4KB, '', true).then((pairs) => {
      assert.notEqual(pairs, null);
    }).catch((err) => {
      assert.equal(err, null);
    });
  });
});

describe('Test Load RSA private key from file', () => {
  it('should succeed loadPrivateKey from file', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private.key');
    const privateKey = rsa.loadPrivateKey(privateKeyData);
    assert.notEqual(null, privateKey);
  });

  it('should succeed loadPrivateKeyAsBase64 from file', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private.key');
    const privateKey = rsa.loadPrivateKeyAsBase64(privateKeyData);
    assert.notEqual(null, privateKey);
  });

  it('should succeed loadPrivateKeyFromBase64 from file', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private_key_base64.txt');
    const privateKey = rsa.loadPrivateKeyFromBase64(privateKeyData);
    assert.notEqual(null, privateKey);
  });

  it('should succeed loadPrivateKeyAsBase64 and loadPrivateKeyAsBase64', () => {
    const privateKeyDataBase64 = fs.readFileSync('./test/testdata/private.key');
    const privateKeyBase64 = rsa.loadPrivateKeyAsBase64(privateKeyDataBase64);

    const privateKey = rsa.loadPrivateKeyFromBase64(privateKeyBase64);

    const bufferEqual = Buffer.compare(Buffer.from(privateKeyBase64, 'base64'), Buffer.from(privateKey)) === 0;
    assert.equal(true, bufferEqual);
  });
});

describe('Test Load RSA public key from file', () => {
  it('should succeed loadPublicKey from file', () => {
    const publicKeyData = fs.readFileSync('./test/testdata/public.key');
    const publicKey = rsa.loadPublicKey(publicKeyData);
    assert.notEqual(null, publicKey);
  });

  it('should succeed loadPublicKeyAsBase64 from file', () => {
    const publicKeyData = fs.readFileSync('./test/testdata/public.key');
    const publicKey = rsa.loadPublicKeyAsBase64(publicKeyData);
    assert.notEqual(null, publicKey);
  });

  it('should succeed loadPublicKeyFromBase64 from file', () => {
    const publicKeyData = fs.readFileSync('./test/testdata/public_key_base64.txt');
    const publicKey = rsa.loadPublicKeyFromBase64(publicKeyData);
    assert.notEqual(null, publicKey);
  });

  it('should succeed loadPublicKeyAsBase64 and loadPublicKeyFromBase64', () => {
    const publicKeyDataBase64 = fs.readFileSync('./test/testdata/public.key');
    const publicKeyBase64 = rsa.loadPublicKeyAsBase64(publicKeyDataBase64);

    const publicKey = rsa.loadPublicKeyFromBase64(publicKeyBase64);

    const bufferEqual = Buffer.compare(Buffer.from(publicKeyBase64, 'base64'), Buffer.from(publicKey)) === 0;
    assert.equal(true, bufferEqual);
  });
});
