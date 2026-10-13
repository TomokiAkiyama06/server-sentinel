/**
 * Lenient reading of a hand-typed invitation code into the one canonical form
 * the server accepts (`server/app/auth/invitation_code.py`,
 * `parse_invitation_code`): 32 characters of the Crockford base32 alphabet
 * `0-9 A-Z` without `I L O U`, upper case, in eight groups of four joined by
 * `-`. The server never guesses, so every leniency lives here:
 *
 * - NFKC first, so full-width letters, digits, spaces and hyphens typed with a
 *   Japanese IME read as their ASCII forms;
 * - case-insensitive;
 * - whitespace and dash-like separators anywhere are ignored (the grouping is
 *   recomputed, so a misplaced separator is harmless);
 * - the Crockford aliases `O` -> `0` and `I` / `L` -> `1`;
 * - `U` and every other character are refused, as is any length other than 32.
 *
 * `null` means "not a code": the page then shows its one generic message and
 * sends nothing.
 */

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const CHARACTERS = 32;
const GROUP = 4;
// ASCII hyphen, the Unicode hyphens and dashes, the minus sign and the
// katakana prolonged sound mark an IME may produce for "-".
const SEPARATORS = /[\s\-‐-―−ーｰ]/gu;
const ALIASES: Record<string, string> = { O: '0', I: '1', L: '1' };

export function normalizeInvitationCode(input: string): string | null {
  if (typeof input !== 'string' || input.length > 256) return null;
  let plain = '';
  for (const character of input.normalize('NFKC').replace(SEPARATORS, '').toUpperCase()) {
    const canonical = ALIASES[character] ?? character;
    if (!ALPHABET.includes(canonical)) return null;
    plain += canonical;
  }
  if (plain.length !== CHARACTERS) return null;
  const groups: string[] = [];
  for (let index = 0; index < CHARACTERS; index += GROUP) groups.push(plain.slice(index, index + GROUP));
  return groups.join('-');
}

/**
 * The optional credential label as the server accepts it
 * (`human_surface._label`): 1-64 characters, no control character and no
 * DEL. Surrounding whitespace is dropped; an empty label is omitted (`null`);
 * an unacceptable one is `undefined` and the page sends nothing.
 */
export function credentialLabel(input: string): string | null | undefined {
  const label = input.trim();
  if (label === '') return null;
  if (Array.from(label).length > 64) return undefined;
  for (const character of label) {
    const code = character.codePointAt(0)!;
    if (code < 32 || code === 127) return undefined;
  }
  return label;
}
