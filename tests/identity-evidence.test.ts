// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPrivateKey,sign} from 'node:crypto';
import {encode} from 'base58-universal';
import {createOanIdentityRecord,signDidDocumentProof,canonicalJson,hashDidDocumentWithProof,hashRegistrationPackageBinding,verifyIdentityEvidence} from '../packages/sdk-ts/src/index.js';

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
  return {input:{expectedDid:resource.did,didDocument:doc,resourcePackage:pkg,registrationVc:vc},policy:{anchor:{rootDid:root.did,verificationMethod:root.verificationMethodId,publicKeyJwk:root.publicKeyJwk},
    observedAt:new Date().toISOString(),maxAgeMs:60000,requirePrivateVc:true,registrar:{did:registrar.did,verificationMethod:registrar.verificationMethodId,publicKeyJwk:registrar.publicKeyJwk}}};
}
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
