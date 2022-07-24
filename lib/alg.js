// https://nodejs.org/api/crypto.html#cryptogeneratekeypairtype-options-callback
// private and public key pair type
exports.RSA_KEY_PAIR = 'rsa';
exports.RSA_PSS_KEY_PAIR = 'rsa-pss';
exports.DSA_KEY_PAIR = 'dsa';
exports.EC_KEY_PAIR = 'ec';
exports.ED25519_KEY_PAIR = 'ed25519';
exports.ED448_KEY_PAIR = 'ed448';
exports.X25519_KEY_PAIR = 'x25519';
exports.X448_KEY_PAIR = 'x448';
exports.DH_KEY_PAIR = 'dh';

// sign Algorithm
exports.RSA_SIGN_MD5 = 'RSA-MD5';
exports.RSA_SIGN_SHA1 = 'RSA-SHA1';
exports.RSA_SIGN_SHA256 = 'RSA-SHA256';
exports.RSA_SIGN_SHA384 = 'RSA-SHA384';
exports.RSA_SIGN_SHA512 = 'RSA-SHA512';
exports.RSA_SIGN_SHA512_224 = 'RSA-SHA512/224';
exports.RSA_SIGN_SHA512_256 = 'RSA-SHA512/256';
exports.RSA_SIGN_SM3 = 'RSA-SM3';

// digest Algorithm
// from Linux Terminal
// $ openssl list -digest-algorithms
exports.MD5_DIGEST = 'md5';
exports.SHA1_DIGEST = 'sha1';
exports.SHA256_DIGEST = 'sha256';
exports.SHA384_DIGEST = 'sha384';
exports.SHA512_DIGEST = 'sha512';

// key generator
exports.HMAC_KEY_GENERATOR = 'hmac';
exports.AES_KEY_GENERATOR = 'aes';

// asymmetric key
exports.PKCS1_PUBLIC_KEY_TYPE = 'pkcs1';
exports.SPKI_PUBLIC_KEY_TYPE = 'spki';

exports.PKCS1_PRIVATE_KEY_TYPE = 'pkcs1';
exports.PKCS8_PRIVATE_KEY_TYPE = 'pkcs8';
exports.SEC1_PRIVATE_KEY_TYPE = 'sec1';

exports.PEM_PUBLIC_PRIVATE_KEY_FORMAT = 'pem';
exports.DER_PUBLIC_PRIVATE_KEY_FORMAT = 'der';
exports.JWK_PUBLIC_PRIVATE_KEY_FORMAT = 'jwk';

// cipher Algorithm
// from Linux Terminal
// $ openssl list -cipher-algorithms
exports.AES_128_CBC = 'aes-128-cbc';
exports.AES_192_CBC = 'aes-192-cbc';
exports.AES_256_CBC = 'aes-256-cbc';

exports.AES_128_GCM = 'aes-128-gcm';
exports.AES_192_GCM = 'aes-192-gcm';
exports.AES_256_GCM = 'aes-256-gcm';

exports.AES_128_CCM = 'aes-128-ccm';
exports.AES_192_CCM = 'aes-192-ccm';
exports.AES_256_CCM = 'aes-256-ccm';

exports.AES_128_OCB = 'aes-128-ocb';
exports.AES_192_OCB = 'aes-192-ocb';
exports.AES_256_OCB = 'aes-256-ocb';

//   'aes-128-cbc',
//   'aes-128-cbc-hmac-sha1',
//   'aes-128-cbc-hmac-sha256',
//   'aes-128-ccm',
//   'aes-128-cfb',
//   'aes-128-cfb1',
//   'aes-128-cfb8',
//   'aes-128-ctr',
//   'aes-128-ecb',
//   'aes-128-gcm',
//   'aes-128-ocb',
//   'aes-128-ofb',
//   'aes-128-xts',
//   'aes-192-cbc',
//   'aes-192-ccm',
//   'aes-192-cfb',
//   'aes-192-cfb1',
//   'aes-192-cfb8',
//   'aes-192-ctr',
//   'aes-192-ecb',
//   'aes-192-gcm',
//   'aes-192-ocb',
//   'aes-192-ofb',
//   'aes-256-cbc',
//   'aes-256-cbc-hmac-sha1',
//   'aes-256-cbc-hmac-sha256',
//   'aes-256-ccm',
//   'aes-256-cfb',
//   'aes-256-cfb1',
//   'aes-256-cfb8',
//   'aes-256-ctr',
//   'aes-256-ecb',
//   'aes-256-gcm',
//   'aes-256-ocb',
//   'aes-256-ofb',
//   'aes-256-xts';