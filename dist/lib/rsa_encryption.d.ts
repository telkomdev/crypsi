export function encryptWithOaepMd5(publicKey: Buffer | RsaPublicKey, data: Buffer): Buffer;
export function encryptWithOaepSha1(publicKey: Buffer | RsaPublicKey, data: Buffer): Buffer;
export function encryptWithOaepSha256(publicKey: Buffer | RsaPublicKey, data: Buffer): Buffer;
export function encryptWithOaepSha384(publicKey: Buffer | RsaPublicKey, data: Buffer): Buffer;
export function encryptWithOaepSha512(publicKey: Buffer | RsaPublicKey, data: Buffer): Buffer;
export function decryptWithOaepMd5(privateKey: Buffer | RsaPrivateKey, encryptedData: Buffer): Buffer;
export function decryptWithOaepSha1(privateKey: Buffer | RsaPrivateKey, encryptedData: Buffer): Buffer;
export function decryptWithOaepSha256(privateKey: Buffer | RsaPrivateKey, encryptedData: Buffer): Buffer;
export function decryptWithOaepSha384(privateKey: Buffer | RsaPrivateKey, encryptedData: Buffer): Buffer;
export function decryptWithOaepSha512(privateKey: Buffer | RsaPrivateKey, encryptedData: Buffer): Buffer;