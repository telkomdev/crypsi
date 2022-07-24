const assert = require('assert');
const fs = require('fs');
const { rsa, rsaSign } = require('../index');

describe('Test RSA Digital Signature', () => {
    it('should valid signing and verifying data with md5', () => {
        const privateKeyData = fs.readFileSync('./test/testdata/private.key');
        const publicKeyData = fs.readFileSync('./test/testdata/public.key');

        const privateKey = rsa.loadPrivateKey(privateKeyData);
        const publicKey = rsa.loadPublicKey(publicKeyData);

        const data = 'hello world';
        const signature = rsaSign.signWithMd5(privateKey, data);
        const signatureValid = rsaSign.verifyWithMd5(publicKey, signature, data);
        
        const expected = true;
        assert.equal(expected, signatureValid);
    });

    it('should valid signing and verifying data with sha256', () => {
        const privateKeyData = fs.readFileSync('./test/testdata/private.key');
        const publicKeyData = fs.readFileSync('./test/testdata/public.key');

        const privateKey = rsa.loadPrivateKey(privateKeyData);
        const publicKey = rsa.loadPublicKey(publicKeyData);

        const data = 'hello world';
        const signature = rsaSign.signWithSha256(privateKey, data);
        const signatureValid = rsaSign.verifyWithSha256(publicKey, signature, data);
        
        const expected = true;
        assert.equal(expected, signatureValid);
    });

    it('should valid signing and verifying data with sha1', () => {
        const privateKeyData = fs.readFileSync('./test/testdata/private.key');
        const publicKeyData = fs.readFileSync('./test/testdata/public.key');

        const privateKey = rsa.loadPrivateKey(privateKeyData);
        const publicKey = rsa.loadPublicKey(publicKeyData);

        const data = 'hello world';
        const signature = rsaSign.signWithSha1(privateKey, data);
        const signatureValid = rsaSign.verifyWithSha1(publicKey, signature, data);
        
        const expected = true;
        assert.equal(expected, signatureValid);
    });

    it('should valid signing and verifying data with sha384', () => {
        const privateKeyData = fs.readFileSync('./test/testdata/private.key');
        const publicKeyData = fs.readFileSync('./test/testdata/public.key');

        const privateKey = rsa.loadPrivateKey(privateKeyData);
        const publicKey = rsa.loadPublicKey(publicKeyData);

        const data = 'hello world';
        const signature = rsaSign.signWithSha384(privateKey, data);
        const signatureValid = rsaSign.verifyWithSha384(publicKey, signature, data);
        
        const expected = true;
        assert.equal(expected, signatureValid);
    });

    it('should valid signing and verifying data with sha512', () => {
        const privateKeyData = fs.readFileSync('./test/testdata/private.key');
        const publicKeyData = fs.readFileSync('./test/testdata/public.key');

        const privateKey = rsa.loadPrivateKey(privateKeyData);
        const publicKey = rsa.loadPublicKey(publicKeyData);

        const data = 'hello world';
        const signature = rsaSign.signWithSha512(privateKey, data);
        const signatureValid = rsaSign.verifyWithSha512(publicKey, signature, data);
        
        const expected = true;
        assert.equal(expected, signatureValid);
    });

});