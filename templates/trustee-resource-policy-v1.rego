package policy

import rego.v1

default allow := false

# Template variables are rendered by the signing service only.
# CAP API never writes or edits this file directly.
expected_init_data_hash := "{{init_data_hash}}"
expected_image_digest := "{{image_digest}}"
expected_signer_subject := "{{signer_subject}}"
expected_signer_issuer := "{{signer_issuer}}"
expected_namespace := "{{namespace}}"
expected_service_account := "{{service_account}}"
expected_identity_hash := "{{identity_hash}}"
expected_resource_path := "{{kbs_resource_path}}"

allow if {
  input.method == "GET"
  attested_workload
  requested_resource_path == expected_resource_path
}

allow if {
  input.method == "PUT"
  attested_workload
  requested_resource_path == expected_resource_path
  input.request.body.operation == "rekey"
  input.request.body.receipt.pubkey_hash_matches
  input.request.body.receipt.signature_valid
  input.request.body.receipt.payload.purpose == "enclava-rekey-v1"
  input.request.body.receipt.payload.resource_path == requested_resource_path
  input.request.body.value_hash_matches
}

allow if {
  input.method == "DELETE"
  attested_workload
  requested_resource_path == expected_resource_path
  input.request.body.operation == "teardown"
  input.request.body.receipt.pubkey_hash_matches
  input.request.body.receipt.signature_valid
  input.request.body.receipt.payload.purpose == "enclava-teardown-v1"
  input.request.body.receipt.payload.resource_path == requested_resource_path
}

attested_workload if {
  input.snp.init_data_hash == expected_init_data_hash
  input.init_data_claims.image_digest == expected_image_digest
  input.init_data_claims.signer_identity.subject == expected_signer_subject
  input.init_data_claims.signer_identity.issuer == expected_signer_issuer
  input.init_data_claims.namespace == expected_namespace
  input.init_data_claims.service_account == expected_service_account
  input.init_data_claims.identity_hash == expected_identity_hash
}

requested_resource_path := concat("/", input["resource-path"])
