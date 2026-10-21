#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Emit the malicious SAML response fixtures for the abuse corpus (SPEC 8.12.18).

One valid base response, then one named mutation per corpus case. The mutation is
the reviewable artefact; the XML is generated, not committed.

These are NOT cryptographically valid signatures - a real signature cannot be
forged here and does not need to be. Each fixture isolates one *structural*
validation failure, which is what SPEC 8.12.18 requires the framework to catch
before any cryptographic check: signature presence and placement, assertion
count, audience, destination, validity window, replay, entity expansion.
The cryptographic cases (a genuinely valid signature over a tampered body)
require a signing key and are added in Phase 25 against a live SimpleSAMLphp.

Usage:  python build_saml.py [outdir]
"""
import os
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', '_generated', 'saml')

ACS = 'https://app.example.com/_/auth/saml/acs'
AUDIENCE = 'https://app.example.com/saml/metadata'
ISSUER = 'https://idp.example.com/'
NOT_AFTER = '2030-01-01T00:00:00Z'

SIG = '''<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:SignatureMethod Algorithm="{alg}"/>
        <ds:Reference URI="#{ref}"/>
      </ds:SignedInfo>
      <ds:SignatureValue>PLACEHOLDER</ds:SignatureValue>
    </ds:Signature>'''


def assertion(aid='_assertion1', audience=AUDIENCE, not_after=NOT_AFTER,
              name_id='reader@example.com', signed=True, alg=None):
    sig = SIG.format(alg=alg or 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', ref=aid) if signed else ''
    return f'''<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}" IssueInstant="2026-10-19T12:00:00Z" Version="2.0">
    <saml:Issuer>{ISSUER}</saml:Issuer>
    {sig}
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="_req1" NotOnOrAfter="{not_after}" Recipient="{ACS}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-10-19T11:59:00Z" NotOnOrAfter="{not_after}">
      <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="groups"><saml:AttributeValue>docs-readers</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>'''


def response(body, destination=ACS, doctype='', rid='_response1', signed_response=True):
    sig = SIG.format(alg='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', ref=rid) if signed_response else ''
    return f'''<?xml version="1.0" encoding="UTF-8"?>
{doctype}<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{rid}" InResponseTo="_req1" Destination="{destination}" IssueInstant="2026-10-19T12:00:00Z" Version="2.0">
  <saml:Issuer>{ISSUER}</saml:Issuer>
  {sig}
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  {body}
</samlp:Response>
'''


# --- the mutations, one per corpus case -------------------------------------
MUTATIONS = {
    'valid_base':
        lambda: response(assertion()),
    'unsigned':
        lambda: response(assertion(signed=False), signed_response=False),
    'response_signed_assertion_unsigned':
        lambda: response(assertion(signed=False)),
    'signature_wrapping':
        # a signed decoy keeps its ID; an unsigned injected assertion carries the
        # attacker's NameID. A validator that checks "a signature exists" and then
        # reads "the first assertion" accepts the wrong subject.
        lambda: response(assertion(aid='_decoy', signed=True)
                         + assertion(aid='_injected', name_id='admin@example.com', signed=False)),
    'alg_none':
        lambda: response(assertion(alg='http://www.w3.org/2000/09/xmldsig#none')),
    'two_assertions':
        lambda: response(assertion(aid='_a1') + assertion(aid='_a2')),
    'wrong_audience':
        lambda: response(assertion(audience='https://attacker.example.net/saml/metadata')),
    'wrong_destination':
        lambda: response(assertion(), destination='https://attacker.example.net/acs'),
    'expired_notonorafter':
        lambda: response(assertion(not_after='2020-01-01T00:00:00Z')),
    'replayed_assertion_id':
        # byte-identical to valid_base: the replay cache, not the parser, must reject it
        lambda: response(assertion()),
    'comment_truncation':
        # CVE-2017-11427 class: a naive text extraction yields "reader@example.com"
        # from a NameID that actually reads "reader@example.com.attacker.net"
        lambda: response(assertion(name_id='reader@example.com<!--x-->.attacker.net')),
    'xxe_external_entity':
        lambda: response(assertion(name_id='&xxe;'),
                         doctype='<!DOCTYPE samlp:Response [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'),
    'encrypted_unsigned':
        lambda: response('<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
                         '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">'
                         '<xenc:CipherData><xenc:CipherValue>UExBQ0VIT0xERVI=</xenc:CipherValue>'
                         '</xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>',
                         signed_response=False),
    'idp_initiated':
        lambda: response(assertion()).replace(' InResponseTo="_req1"', '', 1),
    'clock_skew_130s':
        lambda: response(assertion(not_after='2026-10-19T12:02:10Z')).replace(
            'NotBefore="2026-10-19T11:59:00Z"', 'NotBefore="2026-10-19T12:02:10Z"', 1),
}


def main():
    os.makedirs(OUT, exist_ok=True)
    for name, build in MUTATIONS.items():
        path = os.path.join(OUT, name + '.xml')
        xml = build()
        with open(path, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(xml)
        print('%-38s %6d bytes' % (name, len(xml)))
    print('\n%d fixtures written to %s' % (len(MUTATIONS), os.path.abspath(OUT)))
    print('NOTE: every one except valid_base MUST be rejected, each with a distinct')
    print('audit reason code (SPEC 8.12.18). valid_base is the control: if it is')
    print('rejected too, the test proves nothing.')


if __name__ == '__main__':
    main()
