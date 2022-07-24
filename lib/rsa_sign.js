const { createSign, createVerify } = require('crypto');
const alg = require('./alg');

// signing
const newSigner = (alg) => {
    return createSign(alg);
};

const updateSign = (alg, datas) => {
    const signer = newSigner(alg);
    for (const data of datas) {
        signer.update(data);
    }

    signer.end();

    return signer;
};

exports.signWithMd5 = (privateKey, ...datas) => {
    const signer = updateSign(alg.RSA_SIGN_MD5, datas);
    const signature = signer.sign(privateKey, 'hex');
    return signature;
};

exports.signWithSha1 = (privateKey, ...datas) => {
    const signer = updateSign(alg.RSA_SIGN_SHA1, datas);
    const signature = signer.sign(privateKey, 'hex');
    return signature;
};

exports.signWithSha256 = (privateKey, ...datas) => {
    const signer = updateSign(alg.RSA_SIGN_SHA256, datas);
    const signature = signer.sign(privateKey, 'hex');
    return signature;
};

exports.signWithSha384 = (privateKey, ...datas) => {
    const signer = updateSign(alg.RSA_SIGN_SHA384, datas);
    const signature = signer.sign(privateKey, 'hex');
    return signature;
};

exports.signWithSha512 = (privateKey, ...datas) => {
    const signer = updateSign(alg.RSA_SIGN_SHA512, datas);
    const signature = signer.sign(privateKey, 'hex');
    return signature;
};

// verifying
const newVerifier = (alg) => {
    return createVerify(alg);
};

const updateVerify = (alg, datas) => {
    const verifier = newVerifier(alg);
    for (const data of datas) {
        verifier.update(data);
    }

    verifier.end();

    return verifier;
};

exports.verifyWithMd5 = (publicKey, signature, ...datas) => {
    const verifier = updateVerify(alg.RSA_SIGN_MD5, datas);
    return verifier.verify(publicKey, signature, 'hex');
};

exports.verifyWithSha1 = (publicKey, signature, ...datas) => {
    const verifier = updateVerify(alg.RSA_SIGN_SHA1, datas);
    return verifier.verify(publicKey, signature, 'hex');
};

exports.verifyWithSha256 = (publicKey, signature, ...datas) => {
    const verifier = updateVerify(alg.RSA_SIGN_SHA256, datas);
    return verifier.verify(publicKey, signature, 'hex');
};

exports.verifyWithSha384 = (publicKey, signature, ...datas) => {
    const verifier = updateVerify(alg.RSA_SIGN_SHA384, datas);
    return verifier.verify(publicKey, signature, 'hex');
};

exports.verifyWithSha512 = (publicKey, signature, ...datas) => {
    const verifier = updateVerify(alg.RSA_SIGN_SHA512, datas);
    return verifier.verify(publicKey, signature, 'hex');
};