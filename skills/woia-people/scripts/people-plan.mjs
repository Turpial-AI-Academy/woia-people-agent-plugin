// Pure contribution planning, never provider execution or authority issuance.
const routes = Object.freeze({context:['woia-workforce','workforce.read'],joining:['woia-workforce','workforce.onboarding.record'],assignment:['woia-workforce','workforce.assignment.record'],leaving:['woia-workforce','workforce.offboarding.record'],preparation:['woia-workforce','workforce.competence.record'],guidance:['woia-organization-knowledge','knowledge.read'],coverage:['woia-workforce','workforce.coverage.update'],internal:['woia-communications','communication.internal.send']});
export function planPeople(i) {
 const deny=reason=>({result:'BLOCKED',reason,effect_executed:false});
 if(!i || typeof i!=='object' || !routes[i.method]) return deny('unsupported_method');
 if(i.actor?.authenticated!==true || i.actor.department!=='people' || i.actor.authorized!==true || i.actor.current!==true || i.actor.scope!==i.scope) return deny('actor_scope');
 if(!i.correlation_id || !i.person_ref || !i.scope) return deny('missing_context');
 if(i.effect_status!==undefined && !['NOT_ATTEMPTED','KNOWN','UNKNOWN'].includes(i.effect_status)) return deny('invalid_effect_status');
 const a=i.authority,s=i.source;
 if(a?.accepted!==true || !a.owner || !a.evidence_ref || a.current!==true || a.scope!==i.scope || !Array.isArray(a.actions) || !a.actions.includes(routes[i.method][1])) return deny('authority_required');
 if(!s?.ref || !s.revision || s.status!=='CURRENT' || s.accepted!==true || s.scope!==i.scope) return deny('source_unknown');
 if(!Array.isArray(i.fields) || !Array.isArray(i.allowed_fields) || i.fields.some(f=>!i.allowed_fields.includes(f))) return deny('field_scope');
 if(i.method==='internal' && (i.recipient?.authenticated!==true || i.recipient.authorized!==true || i.recipient.role_context!=='internal-staff' || i.recipient.scope!==i.scope)) return deny('recipient_scope');
 if(['joining','assignment','leaving','preparation','coverage'].includes(i.method) && (!i.decision_ref || !i.period_ref)) return deny('competent_decision_required');
 if(i.method==='guidance' && (s.approved!==true || !i.procedure_version)) return deny('approved_procedure_required');
 if(i.method==='coverage' && (i.coverage?.competence_accepted!==true || i.coverage.authority_current!==true || !i.coverage.period_ref || !i.coverage.owner_acceptance_ref || i.coverage.independent_review_preserved!==true)) return deny('coverage_unaccepted');
 if(i.effect_status==='UNKNOWN') return {result:'RECONCILE_REQUIRED',reason:'retain_before_retry',effect_executed:false,correlation_id:i.correlation_id};
 return {result:'PLANNED_CONTRIBUTION',provider:routes[i.method][0],action:routes[i.method][1],person_ref:i.person_ref,scope:i.scope,fields:[...i.fields],source_ref:s.ref,source_revision:s.revision,correlation_id:i.correlation_id,owner:a.owner,effect_executed:false,authority_granted:false,access_applied:false};
}
export function observeAccess(receipt,grant,expected) {
 const keys=['scope','person_ref','operation','correlation_id','grant_revision','resource_ref','permission_scope'];
 if(!expected || keys.some(k=>typeof expected[k]!=='string' || !expected[k])) return 'UNKNOWN';
 if(!grant || keys.some(k=>grant[k]!==expected[k])) return 'UNKNOWN';
 if(grant.revoked===true) return 'REVOKED';
 if(!receipt || keys.some(k=>receipt[k]!==expected[k]) || receipt.status!=='OBSERVED' || !receipt.evidence_ref || receipt.current!==true) return 'UNKNOWN';
 return receipt.outcome==='REVOKED' ? 'REVOKED' : receipt.outcome==='APPLIED' && grant.accepted===true && grant.current===true ? 'APPLIED' : 'UNKNOWN';
}
