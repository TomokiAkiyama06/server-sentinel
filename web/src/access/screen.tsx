/**
 * Owner access administration (Issue #10 phase 2 S6; routes A1-A6 of S4b,
 * Owner decisions S4-1 .. S4-8, D2, D3, D5, D6, D14).
 *
 * Shown to the Owner only; the server authorizes every request again and this
 * screen widens nothing. It lists each person with their ServerSentinel
 * credentials, issues and re-issues invitation codes, grants and withdraws
 * `live:view` and `recordings:view` independently, and revokes one
 * credential or the whole person. It never shows a Tailscale login or device
 * (D14: the shared account does not tell people apart), and it offers no
 * control on the Owner's own row (S4-3: only the local `recover` changes it).
 *
 * Revocation is credential-scoped: a synced passkey may live on several of
 * its owner's devices, and revoking it ends it on all of them, so no text
 * here calls it a device. A change refused with `step_up_required` asks the
 * Owner to confirm with their passkey and is retried once
 * (`shared/step_up.ts`). An invitation code is shown once, held only in this
 * component's memory and cleared on dismissal, unmount and `pagehide`.
 */
import { useEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import type { AccessCredential, AccessPrincipal, DashboardServices, IssuedInvitation, Permission } from '../domain';
import type { Catalog } from '../i18n';
import { displayNameAcceptable } from '../shared/services';
import { runOwnerChange, type OwnerOutcome } from '../shared/step_up';

type Inventory = { state: 'loading' | 'failed' } | { state: 'ready'; items: readonly AccessPrincipal[] };
type Result = Exclude<OwnerOutcome<unknown>['state'], 'aborted'>;
/** A shown code and the person it admits (to drop it when that person changes). */
export interface Issued extends IssuedInvitation { name: string; principalId: string }

const PERMISSIONS: readonly Permission[] = ['live:view', 'recordings:view'];

/** `YYYY-MM-DD HH:MM UTC` from the server's ISO 8601 UTC string (already validated). */
export function utcStamp(value: string): string {
  return `${value.slice(0, 16).replace('T', ' ')} UTC`;
}

function permissionLabel(t: Catalog, permission: Permission): string {
  return permission === 'live:view' ? t.accessPermissionLive : t.accessPermissionRecordings;
}

export function AccessScreen({ services, t }: { services: DashboardServices; t: Catalog }) {
  const [inventory, setInventory] = useState<Inventory>({ state: 'loading' });
  const [reload, setReload] = useState(0);
  const [busy, setBusy] = useState<string | null>(null);
  const [ceremony, setCeremony] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [issued, setIssued] = useState<Issued | null>(null);
  const [copied, setCopied] = useState<'idle' | 'done' | 'failed'>('idle');
  const [prompt, setPrompt] = useState<((confirmed: boolean) => void) | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [grants, setGrants] = useState<readonly Permission[]>([]);
  const [nameInvalid, setNameInvalid] = useState(false);
  const operation = useRef<AbortController | null>(null);
  const answer = useRef<((confirmed: boolean) => void) | null>(null);
  const load = services.loadPrincipals;

  useEffect(() => {
    if (!load) return;
    const controller = new AbortController();
    setInventory({ state: 'loading' });
    void (async () => {
      try {
        const items = await load(controller.signal);
        if (!controller.signal.aborted) setInventory({ state: 'ready', items });
      } catch {
        if (!controller.signal.aborted) setInventory({ state: 'failed' });
      }
    })();
    return () => controller.abort();
  }, [load, reload]);

  // Leaving the screen abandons the change in flight (an unanswered step-up
  // prompt declines) and drops a code still shown. A page kept in the
  // back-forward cache must not hold the code either.
  useEffect(() => {
    // Synchronous, so the DOM no longer holds the code when the page is frozen.
    // A change still in flight is abandoned too (Codex PR #315): its late
    // answer, a code included, is never applied, and its outcome is unknown.
    // Only `pagehide` (navigation, back-forward cache, closing the tab), not
    // `visibilitychange`: switching to another app to paste the code must
    // keep it shown (PR #315 review).
    const hide = () => {
      const pending = operation.current;
      // The step-up question is open: the change was refused before any
      // commit (`step_up_required`) and is not sent again, so nothing changed.
      const unanswered = answer.current !== null;
      operation.current = null;
      pending?.abort();
      answer.current?.(false);
      flushSync(() => {
        setIssued(null);
        setCopied('idle');
        if (pending) {
          setPrompt(null);
          setCeremony(false);
          setBusy(null);
          setResult(unanswered ? 'not_performed' : 'unknown');
          if (!unanswered) setReload(value => value + 1);
        }
      });
    };
    addEventListener('pagehide', hide);
    return () => {
      removeEventListener('pagehide', hide);
      operation.current?.abort();
      answer.current?.(false);
    };
  }, []);

  if (!load) {
    return <section className="placeholder"><span className="placeholder-mark" aria-hidden="true">◇</span><h2>{t.access}</h2><p>{t.foundation}</p></section>;
  }

  /** `invalidates`: the person whose shown code this change may revoke
   *  (re-issue, revocation); that code is dropped before the request is sent,
   *  whatever its outcome (Codex PR #315). */
  function change<T>(key: string, run: ((signal: AbortSignal) => Promise<T>) | undefined, done?: (value: T) => void,
    invalidates?: string) {
    if (busy !== null || !run) return;
    const controller = new AbortController();
    operation.current = controller;
    if (invalidates !== undefined) setIssued(current => current?.principalId === invalidates ? null : current);
    setBusy(key);
    setConfirming(null);
    setResult(null);
    void (async () => {
      const outcome = await runOwnerChange(run, {
        confirm: () => new Promise<boolean>(resolve => {
          const settle = (confirmed: boolean) => {
            answer.current = null;
            setPrompt(null);
            resolve(confirmed);
          };
          answer.current = settle;
          setPrompt(() => settle);
        }),
        stepUp: services.stepUp,
        onCeremony: () => setCeremony(true),
      }, controller.signal);
      // A late answer after pagehide, unmount or abort is dropped, even one
      // that resolved although its signal was aborted.
      if (outcome.state === 'aborted' || controller.signal.aborted || operation.current !== controller) return;
      operation.current = null;
      setCeremony(false);
      setBusy(null);
      setResult(outcome.state);
      if (outcome.state === 'done') done?.(outcome.value);
      // A committed change, and an unknown one, both make the list stale; a
      // change the server refused before committing leaves it as it was.
      if (outcome.state !== 'not_performed') setReload(value => value + 1);
    })();
  }

  const invite = services.invitePrincipal;
  const reissue = services.reissueInvitation;
  const grant = services.changePermission;
  const revokePerson = services.revokePrincipal;
  const revokeKey = services.revokeCredential;
  const disabled = busy !== null;

  function submitInvite() {
    if (disabled || !invite) return;
    const trimmed = name.trim();
    if (!displayNameAcceptable(trimmed)) { setNameInvalid(true); return; }
    setNameInvalid(false);
    const chosen = PERMISSIONS.filter(permission => grants.includes(permission));
    change('invite', signal => invite(trimmed, chosen, signal), value => {
      setIssued({ name: trimmed, principalId: value.principal_id, code: value.code, expires_at: value.expires_at });
      setCopied('idle');
      setName('');
      setGrants([]);
    });
  }

  async function copy(code: string) {
    try {
      await navigator.clipboard.writeText(code);
      setCopied('done');
    } catch { setCopied('failed'); }
  }

  const message = result === 'done' ? t.accessDone : result === 'not_performed' ? t.accessNotPerformed
    : result === 'unknown' ? t.accessUnknown : null;

  return <div className="access-screen">
    <p className="muted">{t.accessTwoGates}</p>
    <p className="muted">{t.accessStepUpNote}</p>

    {prompt && <StepUpPrompt t={t} onAnswer={confirmed => prompt(confirmed)} />}
    {ceremony && <p role="status">{t.stepUpRunning}</p>}
    {message && <p role={result === 'done' ? 'status' : 'alert'} data-access-result={result}
      className={result === 'done' ? 'access-result' : 'notice-inline'}>{message}</p>}

    {issued && <InvitationCode t={t} issued={issued} copied={copied} onCopy={() => void copy(issued.code)}
      onDismiss={() => { setIssued(null); setCopied('idle'); }} />}

    {invite && <section className="access-invite" aria-labelledby="access-invite-title">
      <h2 id="access-invite-title">{t.accessInviteTitle}</h2>
      <label className="field">{t.accessDisplayName}
        <input type="text" value={name} autoComplete="off" spellCheck={false} disabled={disabled}
          aria-invalid={nameInvalid || undefined}
          onChange={event => { setName(event.target.value); setNameInvalid(false); }}
          onKeyDown={event => { if (event.key === 'Enter' && !event.nativeEvent.isComposing) submitInvite(); }} />
      </label>
      {nameInvalid && <p role="alert">{t.accessDisplayNameInvalid}</p>}
      <fieldset className="access-grants" disabled={disabled}>
        <legend>{t.accessInitialPermissions}</legend>
        {PERMISSIONS.map(permission => <label key={permission}>
          <input type="checkbox" checked={grants.includes(permission)} onChange={event => setGrants(current =>
            event.target.checked ? [...current, permission] : current.filter(item => item !== permission))} />
          {permissionLabel(t, permission)}
        </label>)}
      </fieldset>
      <p className="muted">{t.accessPermissionsIndependent}</p>
      <button type="button" className="primary" disabled={disabled} onClick={submitInvite}>{t.accessInvite}</button>
    </section>}

    {inventory.state === 'loading' && <p role="status">{t.checking}</p>}
    {inventory.state === 'failed' && <section className="notice" role="alert"><p>{t.accessUnavailable}</p>
      <button className="primary" type="button" onClick={() => setReload(value => value + 1)}>{t.retry}</button></section>}
    {inventory.state === 'ready' && <section className="access-people" aria-labelledby="access-people-title">
      <h2 id="access-people-title">{t.accessPeople}</h2>
      {inventory.items.length === 0 && <p>{t.accessNoPeople}</p>}
      {inventory.items.map(person => <PersonCard key={person.id} t={t} person={person} disabled={disabled}
        busy={busy?.endsWith(person.id) ?? false} confirming={confirming} setConfirming={setConfirming} actions={{
          grant: grant && ((permission, granted) => change(`permission:${permission}:${person.id}`,
            signal => grant(person.id, permission, granted, signal))),
          reissue: reissue && (() => change(`reissue:${person.id}`, signal => reissue(person.id, signal), value => {
            setIssued({ name: person.display_name, principalId: person.id, code: value.code, expires_at: value.expires_at });
            setCopied('idle');
          }, person.id)),
          revokeCredential: revokeKey && (credential => change(`credential:${credential.handle}:${person.id}`,
            signal => revokeKey(person.id, credential.handle, signal))),
          revokePerson: revokePerson && (() => change(`principal:${person.id}`, signal => revokePerson(person.id, signal),
            undefined, person.id)),
        }} />)}
    </section>}
  </div>;
}

/** The Owner's controls for one person; an absent one is not offered. */
export interface PersonActions {
  grant?: ((permission: Permission, granted: boolean) => void) | undefined;
  reissue?: (() => void) | undefined;
  revokeCredential?: ((credential: AccessCredential) => void) | undefined;
  revokePerson?: (() => void) | undefined;
}

/** One person: role, status, grants, pending code and credentials. The Owner's
 *  own row and a revoked person's row carry no control (S4-3). */
export function PersonCard({ t, person, disabled, busy = false, confirming, setConfirming, actions }: {
  t: Catalog; person: AccessPrincipal; disabled: boolean; busy?: boolean; confirming: string | null;
  setConfirming: (key: string | null) => void; actions: PersonActions;
}) {
  const managed = person.role !== 'owner' && person.status !== 'revoked';
  const none: PersonActions = {};
  const { grant, reissue, revokeCredential, revokePerson } = managed ? actions : none;
  return <article className="access-person" data-principal-id={person.id} aria-busy={busy || undefined}>
    <h3>{person.display_name}</h3>
    <p>
      <span className="badge">{person.role === 'owner' ? t.owner : t.viewer}</span>{' '}
      <span className={`badge access-status-${person.status}`}>{t[`accessStatus_${person.status}`]}</span>
    </p>
    <dl>
      <dt>{t.accessCreated}</dt><dd className="numeric">{utcStamp(person.created_at)}</dd>
      {person.revoked_at && <><dt>{t.accessRevokedAt}</dt><dd className="numeric">{utcStamp(person.revoked_at)}</dd></>}
    </dl>
    {person.role === 'owner' ? <>
      <p>{t.accessOwnerAll}</p>
      <p className="muted">{t.accessOwnerLocal}</p>
    </> : person.status === 'revoked' ? <p className="muted">{t.accessRevokedNote}</p> : <>
      <div className="access-permissions" role="group" aria-label={t.accessPermissions}>
        {PERMISSIONS.map(permission => {
          const held = person.permissions.includes(permission);
          return <div key={permission} className="access-permission" data-permission={permission} data-granted={held}>
            <span>{permissionLabel(t, permission)}: {held ? t.accessGranted : t.accessNotGranted}</span>
            {grant && <button type="button" disabled={disabled} aria-pressed={held}
              onClick={() => grant(permission, !held)}>{held ? t.accessWithdraw : t.accessGrant}</button>}
          </div>;
        })}
        <p className="muted">{t.accessPermissionSessions}</p>
      </div>
      <p>{person.invitation.pending && person.invitation.expires_at
        ? <>{t.accessInvitationPending}: <span className="numeric">{utcStamp(person.invitation.expires_at)}</span></>
        : t.accessInvitationNone}</p>
      {reissue && (confirming === `reissue:${person.id}` ? <div className="row-actions">
        <p>{t.accessReissueConfirmText}</p>
        <button type="button" className="primary" disabled={disabled} onClick={reissue}>{t.accessReissueConfirm}</button>
        <button type="button" disabled={disabled} onClick={() => setConfirming(null)}>{t.cancel}</button>
      </div> : <button type="button" disabled={disabled} onClick={() => setConfirming(`reissue:${person.id}`)}>
        {t.accessReissue}</button>)}
    </>}
    <Credentials t={t} person={person} disabled={disabled} confirming={confirming} setConfirming={setConfirming}
      onRevoke={revokeCredential} />
    {revokePerson && (confirming === `principal:${person.id}` ? <div className="row-actions">
      <p>{t.accessRevokePersonConfirmText}</p>
      <button type="button" className="danger" disabled={disabled} onClick={revokePerson}>{t.accessRevokePersonConfirm}</button>
      <button type="button" disabled={disabled} onClick={() => setConfirming(null)}>{t.cancel}</button>
    </div> : <button type="button" className="danger" disabled={disabled}
      onClick={() => setConfirming(`principal:${person.id}`)}>{t.accessRevokePerson}</button>)}
  </article>;
}

/** The explicit step-up question: the ceremony starts only from its button. */
export function StepUpPrompt({ t, onAnswer }: { t: Catalog; onAnswer: (confirmed: boolean) => void }) {
  const primary = useRef<HTMLButtonElement>(null);
  useEffect(() => { primary.current?.focus(); }, []);
  return <section className="step-up" role="alertdialog" aria-labelledby="step-up-title" aria-describedby="step-up-text">
    <h2 id="step-up-title">{t.stepUpTitle}</h2>
    <p id="step-up-text">{t.stepUpText}</p>
    <div className="row-actions">
      <button ref={primary} type="button" className="primary" onClick={() => onAnswer(true)}>{t.stepUpConfirm}</button>
      <button type="button" onClick={() => onAnswer(false)}>{t.cancel}</button>
    </div>
  </section>;
}

/** A code shown once: the canonical grouped form (D5), its expiry and how to hand it over. */
export function InvitationCode({ t, issued, copied, onCopy, onDismiss }: {
  t: Catalog; issued: Issued; copied: 'idle' | 'done' | 'failed'; onCopy: () => void; onDismiss: () => void;
}) {
  return <section className="invitation-code" aria-labelledby="invitation-code-title">
    <h2 id="invitation-code-title">{t.invitationCodeTitle}</h2>
    <p>{t.invitationCodeFor}: {issued.name}</p>
    <output className="code" data-invitation-code="true">{issued.code}</output>
    <p>{t.invitationExpires}: <span className="numeric">{utcStamp(issued.expires_at)}</span></p>
    <p className="muted">{t.invitationShownOnce}</p>
    <p className="muted">{t.invitationHandOver}</p>
    <p className="muted">{t.invitationRedeem}</p>
    <div className="row-actions">
      <button type="button" className="primary" onClick={onCopy}>{t.invitationCopy}</button>
      <button type="button" onClick={onDismiss}>{t.invitationDismiss}</button>
    </div>
    {copied === 'done' && <p role="status">{t.invitationCopied}</p>}
    {copied === 'failed' && <p role="alert">{t.invitationCopyFailed}</p>}
  </section>;
}

function Credentials({ t, person, disabled, confirming, setConfirming, onRevoke }: {
  t: Catalog; person: AccessPrincipal; disabled: boolean; confirming: string | null;
  setConfirming: (key: string | null) => void; onRevoke?: ((credential: AccessCredential) => void) | undefined;
}) {
  return <section className="access-credentials" aria-label={t.accessCredentials}>
    <h4>{t.accessCredentials}</h4>
    <p className="muted">{t.accessCredentialScope}</p>
    {person.credentials.length === 0 ? <p>{t.accessNoCredentials}</p> : <ul>
      {person.credentials.map(credential => {
        const key = `credential:${credential.handle}`;
        return <li key={credential.handle} className={`access-credential access-credential-${credential.status}`}>
          <p><strong>{credential.label ?? t.accessNoLabel}</strong>{' '}
            <span className="badge">{t[`credentialStatus_${credential.status}`]}</span></p>
          {credential.status === 'inconsistent' && <p role="note">{t.credentialInconsistent}</p>}
          <dl>
            <dt>{t.credentialSync}</dt>
            <dd>{credential.backup_eligible ? t.credentialSyncable : t.credentialDeviceBound}</dd>
            <dt>{t.credentialBackup}</dt>
            <dd>{credential.backup_state ? t.credentialBackedUp : t.credentialNotBackedUp}</dd>
            <dt>{t.accessCreated}</dt><dd className="numeric">{utcStamp(credential.created_at)}</dd>
            <dt>{t.credentialLastUsed}</dt>
            <dd className="numeric">{credential.last_used_at ? utcStamp(credential.last_used_at) : t.credentialNeverUsed}</dd>
            {credential.revoked_at && <><dt>{t.accessRevokedAt}</dt><dd className="numeric">{utcStamp(credential.revoked_at)}</dd></>}
          </dl>
          {onRevoke && credential.status !== 'revoked' && (confirming === key ? <div className="row-actions">
            <p>{t.credentialRevokeConfirmText}</p>
            <button type="button" className="danger" disabled={disabled}
              onClick={() => onRevoke(credential)}>{t.credentialRevokeConfirm}</button>
            <button type="button" disabled={disabled} onClick={() => setConfirming(null)}>{t.cancel}</button>
          </div> : <button type="button" disabled={disabled}
            onClick={() => setConfirming(key)}>{t.credentialRevoke}</button>)}
        </li>;
      })}
    </ul>}
  </section>;
}
