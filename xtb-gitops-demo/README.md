# XTB GitOps Demo Repository

This repository provides an initial demo setup federating:
- trustbroker-samlmock, oidcdebugger.com relying parties with
- trustbroker-samlmock claims providers here by using the
- DEMO configuration to configure XTB and
- providing mock data to play around

It's intended as a lab to experiment with trustbroker.swiss, in short XTB.

The files in here:

## Texts

Top-level texts resource allow maintaining translation texts before mapping them into ng-translate resources served via the 
translation api endpoint of XTB.

## Configuration

The trustbroker-inventories directory contains the DEMO configuration selected by SPRING_PROFILES_ACTIVE and containing:
- ProfileRP pre-configuring RPs that refer to it.
- SetupRPs are referred to by mock test data (see below) where RelyingParty.id and RelyingParty.Oidc.Client.id mus be unique 
  overall.
- SetupCPs are simulated IDPs served by the samlmock response data.

## Test Data

The trustbroker-samlmock contains the matching test data simulating:
- SAML request messages simulating relying parties.
- SAML response messages simulating users in registries of IDPs.

The SAML request data must be exact in addressing the RelyingParty.id.

The OIDC client_id must be exact in addressing the RelyingParty.Oidc.Client.id.

The SAML response data Issuer exactly addresses the ClaimsParty.id used for response processing. 
With the samlmock is therefore possible to send data of a CP to an RP even though in the federation the setup is not 
configured or the IDP was not selected on the HRD screen.

## Test Data Design

Number-Feature-Message-Summary

- Number allows ordering messages into test sets (01 SAML normal, 02 SSO, ...)
- Features identifies what aspect of XTB is covered.
- Message identifies the type
- Summary identifies the data without needing to read the verbose SAML

Sets:
- 01-DEMO: Shows HRD selection and automatic routing
- 02-SSO: SHows how the SSO feature of XTB works
- 99-ERROR: PEN testing messages showing error handling and miss-configurations if they work
