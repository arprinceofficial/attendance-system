import crypto from 'crypto';

export function generateToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function getTodayDate(): string {
  return new Date().toISOString().split('T')[0];
}

export function getExpiresAt(durationMinutes?: number | null): Date | null {
  if (!durationMinutes || durationMinutes <= 0) return null;
  const expires = new Date();
  expires.setMinutes(expires.getMinutes() + durationMinutes);
  return expires;
}

export function isLinkExpired(expiresAt: Date | null): boolean {
  if (!expiresAt) return false;
  return new Date() > expiresAt;
}
