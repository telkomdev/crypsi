const { createSign, createVerify, constants } = require('crypto');
const alg = require('./alg');

// Note:
// this signature mechanism uses RSA PKCS1 PSS PADDING

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
const commonSignWithPSS = (privateKey, algorithm, datas) => {
  const signer = updateSign(algorithm, datas);
  const signature = signer.sign({
    key: privateKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_AUTO
  }, 'hex');
  return signature;
};

/**
 * @param publicKey {Buffer | VerifyPublicKeyInput}
 * @param algorithm {string}
 * @param signature {string}
 * @param datas {string | Buffer}
 * @return {boolean}
 */
const commonVerifyWithPSS = (publicKey, algorithm, signature, datas) => {
  const verifier = updateVerify(algorithm, datas);
  return verifier.verify({
    key: publicKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_AUTO
  }, signature, 'hex');
};

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithPSSMd5 = (privateKey, ...datas) => commonSignWithPSS(privateKey, alg.RSA_SIGN_MD5, datas);

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithPSSSha1 = (privateKey, ...datas) => commonSignWithPSS(
  privateKey,
  alg.RSA_SIGN_SHA1,
  datas,
);

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithPSSSha256 = (privateKey, ...datas) => commonSignWithPSS(
  privateKey,
  alg.RSA_SIGN_SHA256,
  datas,
);

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithPSSSha384 = (privateKey, ...datas) => commonSignWithPSS(
  privateKey,
  alg.RSA_SIGN_SHA384,
  datas,
);

/**
 * @param privateKey {Buffer | SignPrivateKeyInput}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.signWithPSSSha512 = (privateKey, ...datas) => commonSignWithPSS(
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
exports.verifyWithPSSMd5 = (publicKey, signature, ...datas) => commonVerifyWithPSS(
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
exports.verifyWithPSSSha1 = (publicKey, signature, ...datas) => commonVerifyWithPSS(
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
exports.verifyWithPSSSha256 = (publicKey, signature, ...datas) => commonVerifyWithPSS(
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
exports.verifyWithPSSSha384 = (publicKey, signature, ...datas) => commonVerifyWithPSS(
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
exports.verifyWithPSSSha512 = (publicKey, signature, ...datas) => commonVerifyWithPSS(
  publicKey,
  alg.RSA_SIGN_SHA512,
  signature,
  datas,
);
