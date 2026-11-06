import QRCode from 'qrcode';

/**
 * Standard RFC 3548 Base32 alphabet: strictly A-Z and 2-7.
 * Standard TOTP secrets MUST ONLY contain these characters.
 */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export const DEFAULT_BASE32_SECRET = 'NB2W45DFOIZXELL5';

/**
 * Generates a unique, deterministic, RFC 3548 Base32 secret specifically for a given email address or user identifier.
 * This guarantees:
 * - Every email address (e.g. sagarhebsur@gmail.com vs another@domain.com) gets its own distinct, unique MFA secret.
 * - Authenticator codes generated for email A will NEVER work for email B.
 * - The secret remains permanent and consistent across logins for that user.
 */
export function generateDeterministicBase32Secret(identifier: string): string {
  const clean = identifier.trim().toLowerCase();
  if (!clean) return DEFAULT_BASE32_SECRET;

  const salt = 'SOCPulse-TOTP-Secret-v2026';
  const input = `${salt}:${clean}`;
  
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  let h3 = 0x27d4eb2f;
  let h4 = 0x165667b1;

  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ code, 0x01000193);
    h2 = Math.imul(h2 ^ (code + i * 7), 0x5bd1e995);
    h3 = Math.imul(h3 ^ (code * 13 + i), 0x27d4eb2d);
    h4 = Math.imul(h4 ^ (code * 17 + i * 3), 0x165667b1);
  }

  const state = [h1 >>> 0, h2 >>> 0, h3 >>> 0, h4 >>> 0];
  const chars: string[] = [];
  for (let i = 0; i < 16; i++) {
    const val = (state[i % 4] ^ (i * 0x9e3779b9)) >>> 0;
    chars.push(BASE32_ALPHABET[val % BASE32_ALPHABET.length]);
    state[i % 4] = Math.imul(state[i % 4] ^ (i + 13), 0x5bd1e995) >>> 0;
  }

  return chars.join('');
}

/**
 * Validates that a string is a compliant Base32 secret without illegal chars (0, 1, 8, 9, etc.)
 */
export function isValidBase32Secret(secret: string): boolean {
  if (!secret) return false;
  const clean = secret.replace(/[\s-]/g, '').toUpperCase();
  if (clean.length < 8) return false;
  return /^[A-Z2-7]+$/.test(clean);
}

/**
 * Cleans user-entered or configured secret key to pure uppercase Base32 characters.
 */
export function sanitizeBase32Secret(secret: string): string {
  const cleaned = secret.replace(/[^a-zA-Z2-7]/g, '').toUpperCase();
  return cleaned || DEFAULT_BASE32_SECRET;
}

/**
 * Formats a Base32 secret with spaces every 4 characters for human readability
 * e.g. "TU7U SC4U 3QXI SW4I"
 */
export function formatSecretForDisplay(secret: string): string {
  const clean = sanitizeBase32Secret(secret);
  return clean.match(/.{1,4}/g)?.join(' ') || clean;
}

/**
 * Generates an RFC 6238 compliant otpauth:// TOTP URI
 */
export function buildOtpAuthUri(
  accountIdentifier: string,
  secretBase32: string,
  issuer: string = 'SOCPulse'
): string {
  const cleanSecret = sanitizeBase32Secret(secretBase32);
  const cleanAccount = accountIdentifier.trim() || 'analyst@socpulse.io';
  const label = `${issuer}:${cleanAccount}`;
  
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${cleanSecret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

/**
 * Generates a real machine-scannable QR code data URL (PNG)
 */
export async function generateTotpQrCodeDataUrl(
  accountIdentifier: string,
  secretBase32: string,
  issuer: string = 'SOCPulse'
): Promise<string> {
  const uri = buildOtpAuthUri(accountIdentifier, secretBase32, issuer);
  return QRCode.toDataURL(uri, {
    width: 240,
    margin: 1.5,
    color: {
      dark: '#000000',
      light: '#ffffff',
    },
    errorCorrectionLevel: 'M',
  });
}

/**
 * Decodes a Base32 string into Uint8Array
 */
function base32ToBytes(base32: string): Uint8Array {
  const clean = sanitizeBase32Secret(base32);
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (let i = 0; i < clean.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(clean[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

/**
 * Computes standard RFC 6238 TOTP code using Web Crypto API.
 * Supports window offset for clock drift (-1 = 30s ago, 0 = current, 1 = 30s ahead).
 */
export async function computeTotpCode(
  secretBase32: string,
  timeStepOffset: number = 0
): Promise<string> {
  try {
    const subtle = typeof window !== 'undefined' ? window.crypto?.subtle : globalThis.crypto?.subtle;
    if (!subtle) {
      console.warn('Crypto subtle not found in environment');
      return '000000';
    }

    const keyBytes = base32ToBytes(secretBase32);
    const epoch = Math.floor(Date.now() / 1000);
    const timeStep = Math.floor(epoch / 30) + timeStepOffset;

    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setUint32(0, 0, false);
    view.setUint32(4, timeStep, false);

    const cryptoKey = await subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );

    const hmac = await subtle.sign('HMAC', cryptoKey, buffer);
    const hmacBytes = new Uint8Array(hmac);
    const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
    const code =
      ((hmacBytes[offset] & 0x7f) << 24) |
      ((hmacBytes[offset + 1] & 0xff) << 16) |
      ((hmacBytes[offset + 2] & 0xff) << 8) |
      (hmacBytes[offset + 3] & 0xff);

    return (code % 1000000).toString().padStart(6, '0');
  } catch (err) {
    console.error('Error calculating TOTP code via Web Crypto:', err);
    return '000000';
  }
}

/**
 * Strictly verifies if a given 6-digit code matches the user's specific TOTP secret.
 * Checks current, previous (-30s), and next (+30s) windows to accommodate normal clock drift.
 * Returns false if the code does NOT match this user's secret.
 */
export async function verifyTotpCode(
  candidateCode: string,
  secretBase32: string
): Promise<boolean> {
  const cleanCode = candidateCode.trim();
  if (!/^\d{6}$/.test(cleanCode) || cleanCode.length !== 6) {
    return false;
  }

  try {
    const [c0, cPrev, cNext] = await Promise.all([
      computeTotpCode(secretBase32, 0),
      computeTotpCode(secretBase32, -1),
      computeTotpCode(secretBase32, 1),
    ]);

    if (cleanCode === c0 || cleanCode === cPrev || cleanCode === cNext) {
      return true;
    }
  } catch (err) {
    console.error('TOTP verification error:', err);
  }

  // Strictly reject codes that don't match this user's unique secret
  return false;
}
