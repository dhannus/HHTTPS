/**
 * HHTTPS Role-EAA READ path — v0.5 (enum-free)
 *
 * Turns a VERIFIED presented attestation into the additive token claims
 * (ral + role_claim + role_verification) + HHTTPS-Role-* headers. Two sources:
 *
 *   • EXTERNAL qualified (Q)EAA  (e.g. Ärztekammer)  → RAL2.
 *   • iamhmn-card read back      (HHTTPS-issued)     → the RAL the card carries
 *                                                      (0 self-declared / 1 document).
 *
 * No fixed role list: the occupation is resolved dynamically (ESCO/ISCO/label)
 * via roles.taxonomy.resolveRole. Credibility: a reserved profession may only be
 * emitted at RAL2 (external qualified) or RAL1 (HHTTPS card with a checked
 * document) — never RAL0.
 */

import { buildRoleClaim, guardReservedRole, resolveRole, RESERVED_REGISTRY } from './roles.taxonomy.js';

/**
 * @param {object} args
 * @param {object}  args.roleInput            { label?, isco08?, escoUri?, esco? }
 * @param {number}  [args.ral=2]              2 = external qualified; 0/1 = card read-back
 * @param {boolean} [args.humanVerified=true]
 * @param {string}  [args.authoritativeSource]
 * @returns {{ ok:boolean, error?:string, claims?:object, role?:object, ral?:number }}
 */
export function buildRoleEaaClaims({ roleInput = {}, ral = 2, humanVerified = true, authoritativeSource = null } = {}) {
  if (!roleInput || (!roleInput.label && !roleInput.isco08 && !roleInput.escoUri && !roleInput.esco)) {
    return { ok: false, error: 'roleInput requires at least one of label/isco08/escoUri/esco.' };
  }

  // Map the RAL to the verification method buildRoleClaim understands.
  const method = ral === 2 ? 'eudi-wallet-role'
               : ral === 1 ? 'document-checked'
               : 'self-declared';
  const verificationStatus = ral >= 1 ? 'verified' : 'self-declared';

  const built = buildRoleClaim({ roleInput, verificationStatus, method, humanVerified, authoritativeSource });

  const claims = {
    role:       built.role.id,
    roleLevel:  method,
    ral:        built.ral,
    role_claim: built.role,
    ...(built.verification ? { role_verification: built.verification } : {})
  };
  return { ok: true, claims, role: built.role, ral: built.ral };
}

/**
 * Set HHTTPS-Role-* response headers (ASCII-safe; pass server.js's hdrSafe).
 */
export function setRoleHeaders(res, { ral, role } = {}, hdrSafe = (v) => String(v)) {
  if (!role) return;
  if (role.id)    res.setHeader('HHTTPS-Role', hdrSafe(role.id));
  if (role.label) res.setHeader('HHTTPS-Role-Label', hdrSafe(role.label));
  if (typeof ral === 'number') res.setHeader('HHTTPS-RAL', String(ral));
  if (role.taxonomy?.isco08) res.setHeader('HHTTPS-Role-ISCO08', hdrSafe(role.taxonomy.isco08));
}

/**
 * Guard: a reserved profession must not be emitted below RAL2 unless it is a
 * HHTTPS card with a checked document (RAL1). Never at RAL0.
 * @returns {{ allowed:boolean, reason?:string, sourceHint?:string }}
 */
export function guardRoleEaa({ roleInput = {}, ral = 2, authoritativeSource = null } = {}) {
  const desc = resolveRole(roleInput);
  if (!desc.reserved) return { allowed: true };
  if (ral === 2 && authoritativeSource) return { allowed: true };       // qualified external
  if (ral === 1) return { allowed: true };                               // document-checked card
  const hint = desc.reservedKey && RESERVED_REGISTRY[desc.reservedKey]
    ? RESERVED_REGISTRY[desc.reservedKey].sourceHint : 'a qualified source';
  return { allowed: false, reason: 'reserved-needs-assurance', sourceHint: hint };
}
