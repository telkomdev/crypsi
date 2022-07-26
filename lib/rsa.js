const { generateKeyPair, createPrivateKey, createPublicKey } = require('crypto');
const { Buffer } = require('buffer');
const keyUtil = require('./key_util');
const alg = require('./alg');

/**
 * generate RSA Public and Private Key Pair
 * const keyUtil = require('./lib/key_len');
 * const rsa = require('./lib/rsa');
 * rsa.generateRSAKeyPair(keyUtil.KEY_SIZE_4KB, '').then(pairs => {
 *  console.log(pairs.privateKey);
 *  console.log();
 *  console.log(pairs.publicKey);
 * }).catch(err => {
 *   console.log(err);
 * });
 * @param keySize {number}
 * @param passphrase {string}
 * @param encrypted {boolean}
 */
exports.generateRSAKeyPair = (keySize = keyUtil.KEY_SIZE_2KB,
    passphrase = '', encrypted = false) => {
    if (keySize !== keyUtil.KEY_SIZE_1KB || keySize !== keyUtil.KEY_SIZE_2KB) {
        keySize = keyUtil.KEY_SIZE_2KB
    }

    const options = {
        modulusLength: keySize,
        publicKeyEncoding: {
            type: alg.SPKI_PUBLIC_KEY_TYPE,
            format: alg.PEM_PUBLIC_PRIVATE_KEY_FORMAT
        },
        privateKeyEncoding: {
            type: alg.PKCS8_PRIVATE_KEY_TYPE,
            format: alg.PEM_PUBLIC_PRIVATE_KEY_FORMAT
        }
    };

    if (encrypted) {
        // default cipher for this utility function
        options.cipher = 'aes-256-cbc';
        options.passphrase = passphrase;
    }

    return new Promise((resolve, reject) => {
        generateKeyPair(alg.RSA_KEY_PAIR, options, (err, publicKey, privateKey) => {
            if (err) {
                reject(err);
                return;
            }

            resolve({publicKey, privateKey});
        });
    })
};

/**
 * const privateKeyData = fs.readFileSync('./testdata/private.key');
 * const privateKey = rsa.loadPrivateKey(privateKeyData);
 * console.log(privateKey);
 * @param data {string | Buffer}
 * @return {string | Buffer}
 */
exports.loadPrivateKey = (data) => {
    return createPrivateKey(data).
    export({
        type: alg.PKCS8_PRIVATE_KEY_TYPE,
        format: alg.PEM_PUBLIC_PRIVATE_KEY_FORMAT
    });
};

/**
 * const publicKeyData = fs.readFileSync('./testdata/public.key');
 * const publicKey = rsa.loadPublicKey(publicKeyData);
 * console.log(publicKey);
 * @param data {string | Buffer}
 * @return {string | Buffer}
 */
exports.loadPublicKey = (data) => {
    return createPublicKey(data).
    export({
        type: alg.SPKI_PUBLIC_KEY_TYPE,
        format: alg.PEM_PUBLIC_PRIVATE_KEY_FORMAT
    });
};

/**
 * const privateKeyData = fs.readFileSync('./testdata/public_key_base64.txt');
 * const privateKey = rsa.loadPrivateKeyFromBase64(privateKeyData);
 * console.log(privateKey);
 * @param data {string | Buffer}
 * @return {string | Buffer}
 */
exports.loadPrivateKeyFromBase64 = (data) => {
    if (Buffer.isBuffer(data)) {
        data = data.toString();
    }

    data = Buffer.from(data, 'base64').toString();
    return this.loadPrivateKey(data);
};

/**
 * const publicKeyData = fs.readFileSync('./testdata/public_key_base64.txt');
 * const publicKey = rsa.loadPublicKeyFromBase64(publicKeyData);
 * console.log(publicKey);
 * @param data {string | Buffer}
 * @return {string | Buffer}
 */
exports.loadPublicKeyFromBase64 = (data) => {
    if (Buffer.isBuffer(data)) {
        data = data.toString();
    }

    data = Buffer.from(data, 'base64').toString();
    return this.loadPublicKey(data);
};

/**
 * const privateKeyData = fs.readFileSync('./testdata/private.key');
 * const privateKey = rsa.loadPrivateKeyAsBase64(privateKeyData);
 * console.log(privateKey);
 * @param data {string | Buffer}
 * @return {string}
 */
exports.loadPrivateKeyAsBase64 = (data) => {
    return Buffer.from(this.loadPrivateKey(data)).toString('base64');
};

/**
 * const publicKeyData = fs.readFileSync('./testdata/public.key');
 * const publicKey = rsa.loadPublicKeyAsBase64(publicKeyData);
 * console.log(publicKey);
 * @param data {string | Buffer}
 * @return {string}
 */
exports.loadPublicKeyAsBase64 = (data) => {
    return Buffer.from(this.loadPublicKey(data)).toString('base64');
};
