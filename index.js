exports.keyUtil = require('./lib/key_util');
exports.rsa = require('./lib/rsa');
exports.digest = require('./lib/digest');
exports.hmac = require('./lib/hmac');
exports.rsaSign = require('./lib/rsa_sign');
exports.rsaEncryption = require('./lib/rsa_encryption');
exports.aesEncryption = require('./lib/aes_encryption');

// 762212b184ae7ec00e0c56b52bc000f90cdbede9e023aeb57613276015978f61
// 762212b184ae7ec00e0c56b52bc000f90cdbede9e023aeb57613276015978f61

// afd65188df36664fe69889a2f77fa99045cdf901befeb7243289f256d248c8a4
// afd65188df36664fe69889a2f77fa99045cdf901befeb7243289f256d248c8a4

// bd37d8d3dac43f2a879db849dcd16e186af7ba4983938e4740cb8dc14961b0a0
// bd37d8d3dac43f2a879db849dcd16e186af7ba4983938e4740cb8dc14961b0a0

const key128 = 'ewd$#128djdyAgbj';
const key192 = 'ewd$#128djdyAgbjau&YAnmc';
const key256 = 'ewd$#128djdyAgbjau&YAnmcbagryt5x';

const data = 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyNzk3NDYwMDAsIm9hdXRoX3Rva2VuIjoiMjk1NjY2Njk1MDY0fDIuRXpwem5IRVhZWkJVZmhGQ2l4ZzYzUV9fLjM2MDAuMTI3OTc0NjAwMC0xMDAwMDA0ODMyNzI5MjN8LXJ6U1pnRVBJTktaYnJnX1VNUUNhRzlNdEY4LiIsInVzZXJfaWQiOiIxMDAwMDA0ODMyNzI5MjMifQ';

const encryptedData = this.aesEncryption.encryptWithAes256Cbc(key256, data);
console.log(encryptedData);

const sData = {
   encrypted: '835b1d3c4d3518d60caed277975b6fae9f97d649397f9add26a01085044b89017bc053bab315d72eb5606b06c5c21b3c358eb78f4ae999d9d4f18330e7facbb182ec99fda0da07310c08f442c48bc7aa2b81683691c320c112ea00b7c33519931ccb4d4d450aee9152ca59f6cbc39855f097839b12577d88c7ac683bb08cc6affd8904532e0d905bd4854fe163b26f9ea500ea7b3ff89b75fdbc1205afa080e5dcc14d60f68624491993f54e9e7c0a6e62cf7c228d9f8c0ab213cd1e82affa9b58cd56702f6d04ab3e2eead98d0ea6fbde1be4b673e8914cb6770dd97aba8d440faf00e700a88e6dc3307977b1ba0797cea27246c5eab46d810b90d5618b5f2338a18b7712e7b51ba1604472de06fc50b96e',
   nonce: 'c689d716559427d25c8649e3'
};

const decryptedData = this.aesEncryption.decryptWithAes256Cbc(key256, encryptedData);
console.log(decryptedData);

// const iv = this.keyUtil.generateRandomIV();
// console.log(iv);
// console.log(Buffer.from(iv, 'hex'));