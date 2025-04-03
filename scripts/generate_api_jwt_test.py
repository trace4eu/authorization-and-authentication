#!/usr/bin/env python3
"""
Utility script to generate a JWT admin bearer token, a public JWKS for
Oathkeeper, and store the private key for test signing.

Creates:
- jwks.json (public key only) in Oathkeeper config dir.
- .env file (with bearer token and private key) in test dir.
"""

import argparse
import json
import os
import sys
from pathlib import Path
import time

from jwcrypto import jwk, jwt

# --- Constants ---
KEY_ID = "#key1"
KEY_TYPE = 'EC'
KEY_CURVE = 'P-256'
KEY_USE = "sig"
JWT_ALG = "ES256"
JWT_TYPE = "jwt"
JWT_ISSUER = "authorization-and-authentication-component"
JWT_SUBJECT = "test-script"
JWT_AUDIENCE = "authorization-and-authentication-component"
JWT_LIFETIME_SECONDS = 3600

OATHKEEPER_CONFIG_SUBDIR = "compose/config/oathkeeper"
TEST_SUBDIR = "test"
JWKS_FILENAME = "jwks.json"
ENV_FILENAME = ".env"

# --- Functions ---

"""Generates a new JWK (private+public) and a public-only JWKS dict."""
def generate_key_and_jwks():
    # Generate the full key (contains private parts)
    key = jwk.JWK.generate(kty=KEY_TYPE, crv=KEY_CURVE)
    key.update({"kid": KEY_ID, "use": KEY_USE, "alg": JWT_ALG}) # Add metadata to the key object itself

    # Export ONLY the PUBLIC key parts for the JWKS file
    public_key_dict = key.export_public(as_dict=True)
    public_key_dict["kid"] = key.get("kid", KEY_ID)
    public_key_dict["use"] = key.get("use", KEY_USE)
    public_key_dict["alg"] = key.get("alg", JWT_ALG)


    public_jwks = {'keys': [public_key_dict]}

    # Export the FULL key (including private parts) for test signing use
    private_key_dict = key.export_private(as_dict=True)
    # Ensure metadata is also in the private export if needed by test signer
    private_key_dict["kid"] = key.get("kid", KEY_ID)
    private_key_dict["use"] = key.get("use", KEY_USE)
    private_key_dict["alg"] = key.get("alg", JWT_ALG)

    return key, public_jwks, private_key_dict # Return full key, public JWKS, private key dict

"""Generates a JWT signed with the provided key."""
def generate_jwt(key: jwk.JWK):
    now = int(time.time())
    header = {
        "typ": JWT_TYPE,
        "alg": JWT_ALG,
        "kid": key.get("kid", KEY_ID) # Get kid from the key object
    }
    claims = {
        "iss": JWT_ISSUER,
        "sub": JWT_SUBJECT,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + JWT_LIFETIME_SECONDS,
        "scope": "admin",
    }

    token = jwt.JWT(header=header, claims=claims)
    token.make_signed_token(key)
    return token.serialize()

def main():
    """Parses arguments, generates key/token, and writes files."""
    parser = argparse.ArgumentParser(
        description="Generate JWT Bearer Token, public JWKS, and private key for testing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="Path to the project root directory."
    )
    args = parser.parse_args()

    project_root: Path = args.project_root.resolve()

    oathkeeper_config_dir = project_root / OATHKEEPER_CONFIG_SUBDIR
    test_dir = project_root / TEST_SUBDIR
    jwks_path = oathkeeper_config_dir / JWKS_FILENAME
    env_path = test_dir / ENV_FILENAME

    print(f"Using Project Root: {project_root}")
    print(f"Target Public JWKS path: {jwks_path}")
    print(f"Target .env path:       {env_path}")

    if not (project_root / "compose").is_dir():
        print(f"ERROR: 'compose' directory not found in {project_root}", file=sys.stderr)
        sys.exit(1)
    if not test_dir.is_dir():
        print(f"ERROR: '{TEST_SUBDIR}' directory not found in {project_root}", file=sys.stderr)
        sys.exit(1)

    try:
        private_jwk_obj, public_jwks_dict, private_jwk_dict = generate_key_and_jwks()
    except Exception as e:
        print(f"ERROR: Failed to generate key/JWKS: {e}", file=sys.stderr)
        sys.exit(1)

    # --- Write Public JWKS for Oathkeeper ---
    try:
        oathkeeper_config_dir.mkdir(parents=True, exist_ok=True)
        with open(jwks_path, 'w') as f:
            json.dump(public_jwks_dict, f, indent=2)
        print(f"SUCCESS: Public JWKS file created at: {jwks_path}")
    except (IOError, OSError) as e:
        print(f"ERROR: Could not write public JWKS file to {jwks_path}: {e}", file=sys.stderr)
        sys.exit(1)

    # --- Generate Initial Bearer Token ---
    try:
        # Use the full JWK object (which includes private key) for signing
        initial_bearer_token = generate_jwt(private_jwk_obj)
    except Exception as e:
        print(f"ERROR: Failed to generate initial JWT: {e}", file=sys.stderr)
        sys.exit(1)

    # --- Create .env file with token AND private key ---

    private_key_json_str = json.dumps(private_jwk_dict)

    # WARNING: Ensure this .env file has appropriate permissions!
    env_content = f"""\
# Environment variables for test execution
ADMIN_URL=http://localhost:4445/
TOKEN_URL=http://localhost:4444/oauth2/token

# Initial token generated by script (can be used directly)
BEARER_TOKEN={initial_bearer_token}

# Private JWK (as JSON string) for signing NEW tokens during tests
# Load this in your test setup and parse the JSON to get the key details.
TEST_SIGNING_PRIVATE_JWK='{private_key_json_str}'
"""
    try:
        with open(env_path, 'w') as f:
            f.write(env_content)
        os.chmod(env_path, 0o600) # Set restrictive permissions
        print(f"SUCCESS: .env file created at: {env_path}")
        print(f"          (Permissions set to 600 - Owner Read/Write)")
        print(f"          (Contains initial BEARER_TOKEN and TEST_SIGNING_PRIVATE_JWK)")
    except (IOError, OSError) as e:
        print(f"ERROR: Could not write .env file to {env_path}: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n--- Initial Bearer Token ---")
    print(initial_bearer_token)
    print("\nSUCCESS: Token, public JWKS, and private key (in .env) generated.")

if __name__ == "__main__":
    main()
