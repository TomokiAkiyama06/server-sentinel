/**
 * WebAuthn wire helpers shared by the sign-in shell and the dashboard.
 *
 * This module carries no user-facing text, no product string and no
 * dependency, because the pre-credential sign-in shell bundles it (S5a,
 * `scripts/build.mjs` checks the shell's inputs). The JSON shapes follow the
 * server's verifier (`server/app/auth/webauthn.py`, `_credential_envelope`):
 * strict unpadded base64url, `id` equal to the encoding of `rawId`, `type`
 * `public-key`, and only the response members the verifier reads. The
 * browser's `toJSON()` / `parse*OptionsFromJSON()` are deliberately not used:
 * they are not available in every supported browser and they add members
 * (`clientExtensionResults`, `transports`, ...) the server does not read.
 *
 * Every decoder throws `WireError` on any unexpected shape; callers map it to
 * one fixed local message and never render server content.
 */

export class WireError extends Error {
  constructor() { super('wire'); }
}

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const VALUES = new Map(Array.from(ALPHABET, (character, index) => [character, index]));

/** Unpadded base64url of `bytes`. */
export function base64urlEncode(bytes: ArrayBuffer | ArrayBufferView): string {
  const view = bytes instanceof ArrayBuffer ? new Uint8Array(bytes)
    : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let out = '';
  let index = 0;
  for (; index + 2 < view.length; index += 3) {
    const value = (view[index]! << 16) | (view[index + 1]! << 8) | view[index + 2]!;
    out += ALPHABET[value >> 18]! + ALPHABET[(value >> 12) & 63]! + ALPHABET[(value >> 6) & 63]! + ALPHABET[value & 63]!;
  }
  const rest = view.length - index;
  if (rest === 1) {
    const value = view[index]! << 16;
    out += ALPHABET[value >> 18]! + ALPHABET[(value >> 12) & 63]!;
  } else if (rest === 2) {
    const value = (view[index]! << 16) | (view[index + 1]! << 8);
    out += ALPHABET[value >> 18]! + ALPHABET[(value >> 12) & 63]! + ALPHABET[(value >> 6) & 63]!;
  }
  return out;
}

/**
 * Strict unpadded base64url, as the server decodes it: no padding, no other
 * alphabet, no impossible length, no non-zero trailing bits (one value has
 * one encoding), and at least one byte.
 */
export function base64urlDecode(value: unknown): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 === 1) throw new WireError();
  const out = new Uint8Array(Math.floor(value.length * 3 / 4));
  let bits = 0;
  let buffer = 0;
  let position = 0;
  for (const character of value) {
    const digit = VALUES.get(character);
    if (digit === undefined) throw new WireError();
    buffer = (buffer << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[position++] = (buffer >> bits) & 255;
    }
    buffer &= (1 << bits) - 1;
  }
  if (buffer !== 0 || position !== out.length) throw new WireError();
  return out;
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new WireError();
  return value as Record<string, unknown>;
}

function text(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) throw new WireError();
  return value;
}

function timeout(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) throw new WireError();
  return value;
}

function descriptors(value: unknown): PublicKeyCredentialDescriptor[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 64) throw new WireError();
  return value.map(item => {
    const entry = record(item);
    if (entry.type !== 'public-key') throw new WireError();
    return { type: 'public-key' as const, id: base64urlDecode(entry.id) };
  });
}

function verification(value: unknown): UserVerificationRequirement {
  // The server always requires user verification (AUTH-004); anything else
  // is not a response this page accepts.
  if (value !== 'required') throw new WireError();
  return 'required';
}

/** `navigator.credentials.create` options from the server's JSON. */
export function decodeCreationOptions(json: unknown): PublicKeyCredentialCreationOptions {
  const options = record(json);
  const rp = record(options.rp);
  const user = record(options.user);
  const selection = record(options.authenticatorSelection);
  if (!Array.isArray(options.pubKeyCredParams) || options.pubKeyCredParams.length === 0
      || options.pubKeyCredParams.length > 8) throw new WireError();
  const params = options.pubKeyCredParams.map(item => {
    const entry = record(item);
    if (entry.type !== 'public-key' || typeof entry.alg !== 'number' || !Number.isSafeInteger(entry.alg)) throw new WireError();
    return { type: 'public-key' as const, alg: entry.alg };
  });
  if (selection.residentKey !== 'required' || options.attestation !== 'none') throw new WireError();
  const decoded: PublicKeyCredentialCreationOptions = {
    rp: { id: text(rp.id), name: text(rp.name) },
    user: { id: base64urlDecode(user.id), name: text(user.name), displayName: text(user.displayName) },
    challenge: base64urlDecode(options.challenge),
    pubKeyCredParams: params,
    excludeCredentials: descriptors(options.excludeCredentials),
    authenticatorSelection: {
      residentKey: 'required', requireResidentKey: true,
      userVerification: verification(selection.userVerification),
    },
    attestation: 'none',
  };
  const limit = timeout(options.timeout);
  if (limit !== undefined) decoded.timeout = limit;
  return decoded;
}

/** `navigator.credentials.get` options from the server's JSON. */
export function decodeRequestOptions(json: unknown): PublicKeyCredentialRequestOptions {
  const options = record(json);
  const decoded: PublicKeyCredentialRequestOptions = {
    challenge: base64urlDecode(options.challenge),
    rpId: text(options.rpId),
    userVerification: verification(options.userVerification),
    allowCredentials: descriptors(options.allowCredentials),
  };
  const limit = timeout(options.timeout);
  if (limit !== undefined) decoded.timeout = limit;
  return decoded;
}

function credential(value: Credential | null): PublicKeyCredential {
  if (typeof PublicKeyCredential === 'undefined' || !(value instanceof PublicKeyCredential)
      || value.type !== 'public-key') throw new WireError();
  return value;
}

export interface RegistrationJSON {
  id: string; rawId: string; type: 'public-key';
  response: { clientDataJSON: string; attestationObject: string };
}

export interface AssertionJSON {
  id: string; rawId: string; type: 'public-key';
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle: string | null };
}

/** The registration body member `credential`, exactly the fields the server reads. */
export function serializeRegistration(value: Credential | null): RegistrationJSON {
  const created = credential(value);
  const response = created.response;
  if (typeof AuthenticatorAttestationResponse === 'undefined'
      || !(response instanceof AuthenticatorAttestationResponse)) throw new WireError();
  const rawId = base64urlEncode(created.rawId);
  return {
    id: rawId, rawId, type: 'public-key',
    response: {
      clientDataJSON: base64urlEncode(response.clientDataJSON),
      attestationObject: base64urlEncode(response.attestationObject),
    },
  };
}

/** The authentication / step-up body, exactly the fields the server reads. */
export function serializeAssertion(value: Credential | null): AssertionJSON {
  const asserted = credential(value);
  const response = asserted.response;
  if (typeof AuthenticatorAssertionResponse === 'undefined'
      || !(response instanceof AuthenticatorAssertionResponse)) throw new WireError();
  const rawId = base64urlEncode(asserted.rawId);
  const handle = response.userHandle;
  return {
    id: rawId, rawId, type: 'public-key',
    response: {
      clientDataJSON: base64urlEncode(response.clientDataJSON),
      authenticatorData: base64urlEncode(response.authenticatorData),
      signature: base64urlEncode(response.signature),
      userHandle: handle && handle.byteLength > 0 ? base64urlEncode(handle) : null,
    },
  };
}
