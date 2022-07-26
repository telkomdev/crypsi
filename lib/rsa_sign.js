const { createSign, createVerify } = require('crypto');
const alg = require('./alg');

/**
 * Create new signer
 * @param alg {string}
 * @returns {Sign}
 */
const newSigner = (alg) => {
    return createSign(alg);
};

/**
 * Update signer
 * @param alg {string}
 * @param datas {string | Buffer}
 * @returns {Sign}
 */
const updateSign = (alg, datas) => {
    const signer = newSigner(alg);
    for (const data of datas) {
        signer.update(data);
    }

    signer.end();

    return signer;
};

/**
 *
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param alg {string}
 * @param datas {string | Buffer}
 * @return {string}
 */
const commonSignWith = (privateKey, alg, datas) => {
    const signer = updateSign(alg, datas);
    const signature = signer.sign(privateKey, 'hex');
    return signature;
}

/**
 * @param publicKey {Buffer | VerifyPublicKeyInput}
 * @param alg {string}
 * @param signature {string}
 * @param datas {string | Buffer}
 * @return {boolean}
 */
const commonVerifyWith = (publicKey, alg, signature, datas) => {
    const verifier = updateVerify(alg, datas);
    return verifier.verify(publicKey, signature, 'hex');
}

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithMd5 = (privateKey, ...datas) => {
    return commonSignWith(privateKey, alg.RSA_SIGN_MD5, datas);
};

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithSha1 = (privateKey, ...datas) => {
    return commonSignWith(privateKey, alg.RSA_SIGN_SHA1, datas);
};

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithSha256 = (privateKey, ...datas) => {
    return commonSignWith(privateKey, alg.RSA_SIGN_SHA256, datas);
};

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithSha384 = (privateKey, ...datas) => {
    return commonSignWith(privateKey, alg.RSA_SIGN_SHA384, datas);
};

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithSha512 = (privateKey, ...datas) => {
    return commonSignWith(privateKey, alg.RSA_SIGN_SHA512, datas);
};

/**
 * Create new verifier
 * @param alg {string}
 * @returns {Verify}
 */
const newVerifier = (alg) => {
    return createVerify(alg);
};

/**
 * Update verifier
 * @param alg {string}
 * @param datas {string | Buffer}
 * @returns {Verify}
 */
const updateVerify = (alg, datas) => {
    const verifier = newVerifier(alg);
    for (const data of datas) {
        verifier.update(data);
    }

    verifier.end();

    return verifier;
};

/**
 * @param publicKey {Buffer | VerifyPublicKeyInput}
 * @param datas {string | Buffer}
 * @param signature {string}
 * @returns {boolean}
 */
exports.verifyWithMd5 = (publicKey, signature, ...datas) => {
    return commonVerifyWith(publicKey, alg.RSA_SIGN_MD5, signature, datas);
};

/**
 * @param publicKey {Buffer | VerifyPublicKeyInput}
 * @param datas {string | Buffer}
 * @param signature {String}
 * @returns {Boolean}
 */
exports.verifyWithSha1 = (publicKey, signature, ...datas) => {
    return commonVerifyWith(publicKey, alg.RSA_SIGN_SHA1, signature, datas);
};

/**
 * @param publicKey {Buffer | VerifyPublicKeyInput}
 * @param datas {string | Buffer}
 * @param signature {string}
 * @returns {boolean}
 */
exports.verifyWithSha256 = (publicKey, signature, ...datas) => {
    return commonVerifyWith(publicKey, alg.RSA_SIGN_SHA256, signature, datas);
};

/**
 * @param publicKey {Buffer | VerifyPublicKeyInput}
 * @param datas {string | Buffer}
 * @param signature {string}
 * @returns {boolean}
 */
exports.verifyWithSha384 = (publicKey, signature, ...datas) => {
    return commonVerifyWith(publicKey, alg.RSA_SIGN_SHA384, signature, datas);
};

/**
 * @param publicKey {Buffer | VerifyPublicKeyInput}
 * @param datas {string | Buffer}
 * @param signature {string}
 * @returns {boolean}
 */
exports.verifyWithSha512 = (publicKey, signature, ...datas) => {
    return commonVerifyWith(publicKey, alg.RSA_SIGN_SHA512, signature, datas);
};
