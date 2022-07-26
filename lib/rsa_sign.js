const { createSign, createVerify } = require('crypto');
const alg = require('./alg');

/**
 * Create new signer
 * @param algorithm {string}
 * @returns {Sign}
 */
const newSigner = (algorithm) => createSign(algorithm);

/**
 * Create new verifier
 * @param algorithm {string}
 * @returns {Verify}
 */
const newVerifier = (algorithm) => createVerify(algorithm);

/**
 * Update data of Signer or Verifier
 * @param signerVerifier
 * @param datas
 * @return {*}
 */
const updateSignerVerifierData = (signerVerifier, datas) => {
  for (const data of datas) {
    signerVerifier.update(data);
  }

  signerVerifier.end();

  return signerVerifier;
};

/**
 * Update verifier
 * @param algorithm {string}
 * @param datas {string | Buffer}
 * @returns {Verify}
 */
const updateVerify = (algorithm, datas) => {
  const verifier = newVerifier(algorithm);
  return updateSignerVerifierData(verifier, datas);
};

/**
 * Update signer
 * @param algorithm {string}
 * @param datas {string | Buffer}
 * @returns {Sign}
 */
const updateSign = (algorithm, datas) => {
  const signer = newSigner(algorithm);
  return updateSignerVerifierData(signer, datas);
};

/**
 *
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param algorithm {string}
 * @param datas {string | Buffer}
 * @return {string}
 */
const commonSignWith = (privateKey, algorithm, datas) => {
  const signer = updateSign(algorithm, datas);
  const signature = signer.sign(privateKey, 'hex');
  return signature;
};

/**
 * @param publicKey {Buffer | VerifyPublicKeyInput}
 * @param algorithm {string}
 * @param signature {string}
 * @param datas {string | Buffer}
 * @return {boolean}
 */
const commonVerifyWith = (publicKey, algorithm, signature, datas) => {
  const verifier = updateVerify(algorithm, datas);
  return verifier.verify(publicKey, signature, 'hex');
};

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithMd5 = (privateKey, ...datas) => commonSignWith(privateKey, alg.RSA_SIGN_MD5, datas);

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithSha1 = (privateKey, ...datas) => commonSignWith(
  privateKey,
  alg.RSA_SIGN_SHA1,
  datas,
);

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithSha256 = (privateKey, ...datas) => commonSignWith(
  privateKey,
  alg.RSA_SIGN_SHA256,
  datas,
);

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithSha384 = (privateKey, ...datas) => commonSignWith(
  privateKey,
  alg.RSA_SIGN_SHA384,
  datas,
);

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithSha512 = (privateKey, ...datas) => commonSignWith(
  privateKey,
  alg.RSA_SIGN_SHA512,
  datas,
);

/**
 * @param publicKey {Buffer | VerifyPublicKeyInput}
 * @param datas {string | Buffer}
 * @param signature {string}
 * @returns {boolean}
 */
exports.verifyWithMd5 = (publicKey, signature, ...datas) => commonVerifyWith(
  publicKey,
  alg.RSA_SIGN_MD5,
  signature,
  datas,
);

/**
 * @param publicKey {Buffer | VerifyPublicKeyInput}
 * @param datas {string | Buffer}
 * @param signature {String}
 * @returns {Boolean}
 */
exports.verifyWithSha1 = (publicKey, signature, ...datas) => commonVerifyWith(
  publicKey,
  alg.RSA_SIGN_SHA1,
  signature,
  datas,
);

/**
 * @param publicKey {Buffer | VerifyPublicKeyInput}
 * @param datas {string | Buffer}
 * @param signature {string}
 * @returns {boolean}
 */
exports.verifyWithSha256 = (publicKey, signature, ...datas) => commonVerifyWith(
  publicKey,
  alg.RSA_SIGN_SHA256,
  signature,
  datas,
);

/**
 * @param publicKey {Buffer | VerifyPublicKeyInput}
 * @param datas {string | Buffer}
 * @param signature {string}
 * @returns {boolean}
 */
exports.verifyWithSha384 = (publicKey, signature, ...datas) => commonVerifyWith(
  publicKey,
  alg.RSA_SIGN_SHA384,
  signature,
  datas,
);

/**
 * @param publicKey {Buffer | VerifyPublicKeyInput}
 * @param datas {string | Buffer}
 * @param signature {string}
 * @returns {boolean}
 */
exports.verifyWithSha512 = (publicKey, signature, ...datas) => commonVerifyWith(
  publicKey,
  alg.RSA_SIGN_SHA512,
  signature,
  datas,
);
