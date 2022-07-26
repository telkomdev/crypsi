const { createSign, createVerify } = require('crypto');
const alg = require('./alg');

/**
 * Create new signer
 * @param alg {String}
 * @returns {Sign}
 */
const newSigner = (alg) => {
    return createSign(alg);
};

/**
 * Update signer
 * @param alg {String}
 * @param datas {Array<BinaryLike>}
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
 * @param privateKey
 * @param datas {BinaryLike}
 * @returns {string}
 */
exports.signWithMd5 = (privateKey, ...datas) => {
    const signer = updateSign(alg.RSA_SIGN_MD5, datas);
    const signature = signer.sign(privateKey, 'hex');
    return signature;
};

/**
 * @param privateKey
 * @param datas {BinaryLike}
 * @returns {string}
 */
exports.signWithSha1 = (privateKey, ...datas) => {
    const signer = updateSign(alg.RSA_SIGN_SHA1, datas);
    const signature = signer.sign(privateKey, 'hex');
    return signature;
};

/**
 * @param privateKey
 * @param datas {BinaryLike}
 * @returns {string}
 */
exports.signWithSha256 = (privateKey, ...datas) => {
    const signer = updateSign(alg.RSA_SIGN_SHA256, datas);
    const signature = signer.sign(privateKey, 'hex');
    return signature;
};

/**
 * @param privateKey
 * @param datas {BinaryLike}
 * @returns {string}
 */
exports.signWithSha384 = (privateKey, ...datas) => {
    const signer = updateSign(alg.RSA_SIGN_SHA384, datas);
    const signature = signer.sign(privateKey, 'hex');
    return signature;
};

/**
 * @param privateKey
 * @param datas {BinaryLike}
 * @returns {string}
 */
exports.signWithSha512 = (privateKey, ...datas) => {
    const signer = updateSign(alg.RSA_SIGN_SHA512, datas);
    const signature = signer.sign(privateKey, 'hex');
    return signature;
};

/**
 * Create new verifier
 * @param alg {String}
 * @returns {Verify}
 */
const newVerifier = (alg) => {
    return createVerify(alg);
};

/**
 * Update verifier
 * @param alg {String}
 * @param datas {Array<BinaryLike>}
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
 * @param publicKey {VerifyPublicKeyInput}
 * @param datas {BinaryLike}
 * @param signature {String}
 * @returns {Boolean}
 */
exports.verifyWithMd5 = (publicKey, signature, ...datas) => {
    const verifier = updateVerify(alg.RSA_SIGN_MD5, datas);
    return verifier.verify(publicKey, signature, 'hex');
};

/**
 * @param publicKey {VerifyPublicKeyInput}
 * @param datas {BinaryLike}
 * @param signature {String}
 * @returns {Boolean}
 */
exports.verifyWithSha1 = (publicKey, signature, ...datas) => {
    const verifier = updateVerify(alg.RSA_SIGN_SHA1, datas);
    return verifier.verify(publicKey, signature, 'hex');
};

/**
 * @param publicKey {VerifyPublicKeyInput}
 * @param datas {BinaryLike}
 * @param signature {String}
 * @returns {Boolean}
 */
exports.verifyWithSha256 = (publicKey, signature, ...datas) => {
    const verifier = updateVerify(alg.RSA_SIGN_SHA256, datas);
    return verifier.verify(publicKey, signature, 'hex');
};

/**
 * @param publicKey {VerifyPublicKeyInput}
 * @param datas {BinaryLike}
 * @param signature {String}
 * @returns {Boolean}
 */
exports.verifyWithSha384 = (publicKey, signature, ...datas) => {
    const verifier = updateVerify(alg.RSA_SIGN_SHA384, datas);
    return verifier.verify(publicKey, signature, 'hex');
};

/**
 * @param publicKey {VerifyPublicKeyInput}
 * @param datas {BinaryLike}
 * @param signature {String}
 * @returns {Boolean}
 */
exports.verifyWithSha512 = (publicKey, signature, ...datas) => {
    const verifier = updateVerify(alg.RSA_SIGN_SHA512, datas);
    return verifier.verify(publicKey, signature, 'hex');
};
