// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPrivateKey,sign} from 'node:crypto';
import {encode} from 'base58-universal';
import {createOanIdentityRecord,signDidDocumentProof,canonicalJson,hashDidDocumentWithProof,hashRegistrationPackageBinding,verifyIdentityEvidence,verifyPinnedRootPackage} from '../packages/sdk-ts/src/index.js';

async function fixture(){
  const resource=await createOanIdentityRecord({label:'evidence',kind:'agent',resourceType:'skill'});
  const root=await createOanIdentityRecord({label:'root',kind:'agent',resourceType:'skill'});
  const registrar=await createOanIdentityRecord({label:'registrar',kind:'agent',resourceType:'skill'});
  const doc=JSON.parse(JSON.stringify(await signDidDocumentProof(resource.didDocument,resource)));
  const hash=(v:unknown)=>createHash('sha256').update(canonicalJson(v),'utf8').digest('hex');
  const pkg:any={resourceDid:resource.did,resourceType:'skill',packageVersion:'1.0.0',didDocument:doc,
    didDocumentHash:await hashDidDocumentWithProof(doc),metadataHash:'',packageHash:'',hashAlgorithm:'sha256',
    metadata:{resourceDid:resource.did,resourceType:'skill',subjectType:'skill',subjectDid:resource.did,
      name:'evidence',description:'test',capabilityTags:[],authorizedDomains:doc.oanMetadata.authorizedDomains??[],protocolBindings:[],services:[],
      lifecycleState:'active',packageVersion:'1.0.0',metadataHash:'',packageHash:'',hashAlgorithm:'sha256',updatedAt:new Date().toISOString()},createdAt:new Date().toISOString()};
  pkg.metadataHash=hash(pkg.metadata);pkg.metadata.metadataHash=pkg.metadataHash;
  pkg.packageHash=await hashRegistrationPackageBinding(pkg);pkg.metadata.packageHash=pkg.packageHash;
  const claims={resourceDid:pkg.resourceDid,resourceType:'skill',version:pkg.packageVersion,didDocumentHash:pkg.didDocumentHash,
    metadataHash:pkg.metadataHash,packageHash:pkg.packageHash,hashAlgorithm:'sha256',lifecycleState:'active',authorizedDomains:pkg.metadata.authorizedDomains};
  const proof=(identity:any,body:unknown)=>({type:'Ed25519Signature2020',verificationMethod:identity.verificationMethodId,creator:identity.verificationMethodId,
    proofPurpose:'assertionMethod',cryptoSuite:'ed25519-sha256',hashAlgorithm:'sha256',proofValue:'z'+encode(sign(null,Buffer.from(canonicalJson(body),'utf8'),createPrivateKey({key:identity.privateKeyJwk,format:'jwk'})))});
  pkg.rootProof={rootDid:root.did,packageClaims:claims,proof:proof(root,claims)};
  const vc:any={issuer:registrar.did,type:['VerifiableCredential','OANResourceRegistrationCredential'],issuanceDate:new Date().toISOString(),
    credentialSubject:{id:resource.did,registrarDid:registrar.did,packageVersion:pkg.packageVersion,didDocumentHash:pkg.didDocumentHash,metadataHash:pkg.metadataHash,packageHash:pkg.packageHash}};
  vc.proof=proof(registrar,vc);
  return {resignVc(){const {proof:previous,...unsigned}=vc;vc.proof={...previous,proofValue:proof(registrar,unsigned).proofValue};},
    input:{expectedDid:resource.did,didDocument:doc,resourcePackage:pkg,registrationVc:vc},policy:{anchor:{rootDid:root.did,verificationMethod:root.verificationMethodId,publicKeyJwk:root.publicKeyJwk},
    observedAt:new Date().toISOString(),maxAgeMs:60000,requirePrivateVc:true,registrar:{did:registrar.did,verificationMethod:registrar.verificationMethodId,publicKeyJwk:registrar.publicKeyJwk}}};
}

test('optional private VC is not required for public L1; supplied invalid VC still fails',async()=>{
  const {input,policy}=await fixture();
  const publicPolicy={...policy,requirePrivateVc:false};
  const report=await verifyIdentityEvidence({...input,registrationVc:undefined},publicPolicy);
  assert.equal(report.valid,true);assert.equal(report.checks.find(c=>c.name==='privateVc')?.status,'not_checked');
  const invalid=structuredClone(input);invalid.registrationVc.proof.proofValue='z111';
  assert.equal((await verifyIdentityEvidence(invalid,publicPolicy)).valid,false);
  assert.equal((await verifyIdentityEvidence(input,{...policy,registrar:undefined})).valid,false);
});

const vcChanges:Record<string,(vc:any)=>void>={
  'wrong subject':vc=>{vc.credentialSubject.id='did:oan:other';},
  'wrong registrar':vc=>{vc.credentialSubject.registrarDid='did:oan:other';},
  'wrong verification method':vc=>{vc.proof.verificationMethod='did:oan:other#key-1';},
  'wrong purpose':vc=>{vc.proof.proofPurpose='authentication';},
  'wrong credential type':vc=>{vc.type=['VerifiableCredential'];},
  'wrong document hash':vc=>{vc.credentialSubject.didDocumentHash='00';},
  'wrong metadata hash':vc=>{vc.credentialSubject.metadataHash='00';},
  'wrong package hash':vc=>{vc.credentialSubject.packageHash='00';},
  'invalid issuance':vc=>{vc.issuanceDate='invalid';},
  'future issuance':vc=>{vc.issuanceDate='2099-01-01T00:00:00Z';},
  'expired credential':vc=>{vc.expirationDate='2000-01-01T00:00:00Z';},
  'unknown proof type':vc=>{vc.proof.type='UnknownProof';},
};
for(const [name,change] of Object.entries(vcChanges))test('private VC independently rejects '+name,async()=>{
  const {input,policy,resignVc}=await fixture();change(input.registrationVc);resignVc();
  const report=await verifyIdentityEvidence(input,policy);
  assert.equal(report.valid,false);assert.equal(report.checks.find(c=>c.name==='privateVc')?.status,'failed');
  assert.equal(report.checks.find(c=>c.name==='registrationTrust')?.status,'passed','public Root evidence remains valid');
});

for(const [name,change] of Object.entries({
  'different Root':(p:any)=>{p.anchor.rootDid='did:oan:other';},
  'wrong Root key':(p:any)=>{p.anchor.publicKeyJwk.x='A'.repeat(43);},
  'different Root method':(p:any)=>{p.anchor.verificationMethod+='-other';},
  'expired observation':(p:any)=>{p.observedAt='2000-01-01T00:00:00Z';},
  'future observation':(p:any)=>{p.observedAt='2099-01-01T00:00:00Z';},
  'zero max age':(p:any)=>{p.maxAgeMs=0;},
  'infinite max age':(p:any)=>{p.maxAgeMs=Infinity;},
}))test('Root evidence rejects '+name,async()=>{
  const {input,policy}=await fixture();change(policy);
  assert.equal((await verifyIdentityEvidence(input,policy)).valid,false);
});

test('direct pinned package verifier snapshots Root policy, package and clock before awaiting crypto',async()=>{
  const {input,policy}=await fixture();
  const args={...policy,resourcePackage:input.resourcePackage,expectedDid:input.expectedDid,now:Date.now()};
  const pending=verifyPinnedRootPackage(args);
  args.anchor.publicKeyJwk.x='invalid';args.resourcePackage.metadata.name='unapproved';args.now=Infinity;
  assert.equal((await pending).document.id,input.expectedDid);
});
test('Root-bound public package and canonical Registrar VC are independently checked',async()=>{
  const {input,policy}=await fixture();const report=await verifyIdentityEvidence(input,policy);
  assert.equal(report.valid,true,JSON.stringify(report));
  for(const name of ['documentSignature','documentBinding','registrationTrust','freshness','registrationStatus','privateVc'])assert.equal(report.checks.find(c=>c.name===name)?.status,'passed');
  for(const name of ['governance','controllerBinding','liveRevocation'])assert.equal(report.checks.find(c=>c.name===name)?.status,'not_checked');
  for(const mutate of [
    (v:any)=>{v.didDocument.id='wrong';},
    (v:any)=>{v.resourcePackage.metadata.name='tampered';},
    (v:any)=>{v.resourcePackage.rootProof.proof.proofValue='z111';},
    (v:any)=>{v.resourcePackage.metadata.lifecycleState='revoked';},
    (v:any)=>{v.registrationVc.credentialSubject.packageVersion='2';},
    (v:any)=>{v.didDocument.authentication=[];},
  ]){const bad=structuredClone(input);mutate(bad);assert.equal((await verifyIdentityEvidence(bad,policy)).valid,false);}
  assert.equal((await verifyIdentityEvidence(input,{...policy,observedAt:'2000-01-01T00:00:00Z'})).valid,false);
  assert.equal((await verifyIdentityEvidence({...input,resourcePackage:undefined},policy)).valid,false);
  assert.equal((await verifyIdentityEvidence({...input,registrationVc:undefined},policy)).valid,false);
  assert.equal((await verifyIdentityEvidence(null as any,policy)).valid,false);
});

test('evidence snapshots caller data and policy before awaiting crypto',async()=>{
  const {input,policy}=await fixture();
  const pending=verifyIdentityEvidence(input,policy);
  input.resourcePackage.metadata.name='changed while pending';
  input.registrationVc.credentialSubject.packageHash='changed';
  policy.anchor.publicKeyJwk.x='wrong';
  assert.equal((await pending).valid,true);
});

test('untrusted evidence rejects secrets, excessive depth/size, unknown context and unknown proof profile',async()=>{
  const {input,policy}=await fixture();
  for(const change of [
    (v:any)=>{v.didDocument.privateKeyJwk={d:'never-public'};},
    (v:any)=>{v.didDocument.extra='x'.repeat(1_000_001);},
    (v:any)=>{let nested:any={};v.didDocument.extra=nested;for(let i=0;i<40;i++){nested.next={};nested=nested.next;}},
    (v:any)=>{v.didDocument['@context'].push('http://169.254.169.254/latest/meta-data');},
    (v:any)=>{v.registrationVc.issuer='wrong';},
    (v:any)=>{v.registrationVc.proof.proofValue='z111';},
  ]){const candidate=structuredClone(input);change(candidate);const report=await verifyIdentityEvidence(candidate,policy);assert.equal(report.valid,false);assert(!JSON.stringify(report).includes('never-public'));}
  assert.equal((await verifyIdentityEvidence(input,{...policy,now:NaN})).valid,false);
  assert.equal((await verifyIdentityEvidence(input,{...policy,registrar:{...policy.registrar,proofProfile:'unknown' as any}})).valid,false);
  const previous=globalThis.fetch;let requests=0;globalThis.fetch=(async()=>{requests++;throw new Error('unexpected network');}) as typeof fetch;
  try{const bad=structuredClone(input);(bad.didDocument['@context'] as string[]).push('https://untrusted.invalid/context');assert.equal((await verifyIdentityEvidence(bad,policy)).valid,false);assert.equal(requests,0);}
  finally{globalThis.fetch=previous;}
});
