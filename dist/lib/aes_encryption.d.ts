export function encryptWithAes128Cbc(key: string, data: string | Buffer): {
    encrypted: string;
    nonce;
};
export function encryptWithAes192Cbc(key: string, data: string | Buffer): {
    encrypted: string;
    nonce;
};
export function encryptWithAes256Cbc(key: string, data: string | Buffer): {
    encrypted: string;
    nonce;
};
export function decryptWithAes128Cbc(key: string, data: string | Buffer): Buffer;
export function decryptWithAes192Cbc(key: string, data: string | Buffer): Buffer;
export function decryptWithAes256Cbc(key: string, data: string | Buffer): Buffer;
export function encryptWithAes128Gcm(key: string, data: string | Buffer): {
    encrypted: string;
    nonce;
};
export function encryptWithAes192Gcm(key: string, data: string | Buffer): {
    encrypted: string;
    nonce;
};
export function encryptWithAes256Gcm(key: string, data: string | Buffer): {
    encrypted: string;
    nonce;
};
export function decryptWithAes128Gcm(key: string, data: string | Buffer): Buffer;
export function decryptWithAes192Gcm(key: string, data: string | Buffer): Buffer;
export function decryptWithAes256Gcm(key: string, data: string | Buffer): Buffer;
export function encryptWithAes128Ccm(key: string, data: string | Buffer): {
    encrypted: string;
    nonce;
};
export function encryptWithAes192Ccm(key: string, data: string | Buffer): {
    encrypted: string;
    nonce;
};
export function encryptWithAes256Ccm(key: string, data: string | Buffer): {
    encrypted: string;
    nonce;
};
export function decryptWithAes128Ccm(key: string, data: string | Buffer): Buffer;
export function decryptWithAes192Ccm(key: string, data: string | Buffer): Buffer;
export function decryptWithAes256Ccm(key: string, data: string | Buffer): Buffer;
export function encryptWithAes128Ocb(key: string, data: string | Buffer): {
    encrypted: string;
    nonce;
};
export function encryptWithAes192Ocb(key: string, data: string | Buffer): {
    encrypted: string;
    nonce;
};
export function encryptWithAes256Ocb(key: string, data: string | Buffer): {
    encrypted: string;
    nonce;
};
export function decryptWithAes128Ocb(key: string, data: string | Buffer): Buffer;
export function decryptWithAes192Ocb(key: string, data: string | Buffer): Buffer;
export function decryptWithAes256Ocb(key: string, data: string | Buffer): Buffer;
