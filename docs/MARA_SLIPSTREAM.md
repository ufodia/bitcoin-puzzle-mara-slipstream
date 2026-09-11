# MARA Slipstream adapter

## Purpose

The Relay submits a previously signed raw Bitcoin transaction to MARA's Slipstream service without first sending it to a public Bitcoin P2P node or public broadcast API.

## Isolation

Production HTTP logic lives only in:

```text
crates/puzzle-slipstream-core/src/relay.rs
```

The offline Signer package does not enable or depend on that module.

## Request body

The adapter sends JSON with the signed transaction and, when supplied by the operator, an optional client code:

```json
{
  "tx_hex": "SIGNED_RAW_TRANSACTION_HEX",
  "client_code": "OPTIONAL_CODE"
}
```

## Fail-closed behavior

- Only compiled endpoint profiles are accepted.
- Production requires a mainnet-capable build.
- Redirects are rejected.
- Environment/system proxy use is disabled.
- Requests have a fixed timeout and response-size cap.
- The raw transaction is never placed in errors or logs.
- Non-success HTTP status is not treated as acceptance.
- A success response is labeled “relay accepted — not confirmed.”
- There is no public broadcast fallback and no automatic retry to another relay.

## API drift

Slipstream is a third-party service. Paths, required headers, fee rules, limits, terms, availability, and response fields can change independently of this repository. Before mainnet use:

1. compare the compiled endpoint and request body with current official MARA documentation;
2. review the diff and rebuild from source;
3. test the local mock adapter;
4. test with a valueless transaction on an appropriate supported network when possible;
5. stop if the live service contract differs.

The generic response parser retains a bounded, redacted receipt because the service may add response fields. It never interprets HTTP success as block confirmation.

## Not affiliated

This independent adapter is not sponsored, endorsed, audited, or guaranteed by MARA Holdings, Inc.
