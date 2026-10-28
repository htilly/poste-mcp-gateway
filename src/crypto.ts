import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

/**
 * Seals small secrets (IMAP passwords) with AES-256-GCM. The output is
 * `v1.<iv>.<tag>.<ciphertext>`, all base64url, so it can live in a JSON file.
 * `aad` binds a sealed value to its owner, so a ciphertext copied onto another
 * grant fails to open.
 */
export class Vault {
  constructor(private readonly key: Buffer) {
    if (key.length !== 32) throw new Error('vault key must be 32 bytes');
  }

  seal(plaintext: string, aad: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(aad, 'utf8'));
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return ['v1', iv, cipher.getAuthTag(), ct].map(p => (typeof p === 'string' ? p : p.toString('base64url'))).join('.');
  }

  open(sealed: string, aad: string): string {
    const [version, iv, tag, ct] = sealed.split('.');
    if (version !== 'v1' || !iv || !tag || ct === undefined) throw new Error('malformed sealed value');
    const authTag = Buffer.from(tag, 'base64url');
    // Node accepts truncated GCM tags unless told otherwise; only full 16-byte tags are valid here.
    if (authTag.length !== 16) throw new Error('malformed sealed value');
    const decipher = createDecipheriv('aes-256-gcm', this.key, Buffer.from(iv, 'base64url'), { authTagLength: 16 });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(Buffer.from(ct, 'base64url')), decipher.final()]).toString('utf8');
  }
}

/** A random opaque token, 256 bits. */
export function newToken(): string {
  return randomBytes(32).toString('base64url');
}

/** Tokens are only ever stored hashed, so a leaked state file holds no live bearer tokens. */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('base64url');
}
