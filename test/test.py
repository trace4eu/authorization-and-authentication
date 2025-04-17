"""
Test suite for TRACE4EU authorization and authentication component.
"""

import allure
import requests
import json
import base64
import uuid
import time
import os
import pytest
from jwcrypto import jwk, jwt
from dotenv import load_dotenv

# --- Configuration and Setup ---
load_dotenv() # Load variables from .env file

ADMIN_URL = os.getenv("ADMIN_URL", "http://localhost:4445/")
TOKEN_URL = os.getenv("TOKEN_URL", "http://localhost:4444/oauth2/token")

# Load the Bearer token and Private Key JSON string from env variables
BEARER_TOKEN = os.getenv("BEARER_TOKEN")
TEST_SIGNING_PRIVATE_JWK_JSON = os.getenv("TEST_SIGNING_PRIVATE_JWK")

# Constants for tests
DEFAULT_TEST_SCOPE = "http://trace4.eu/ocs/item1,read http://trace4.eu/ocs/item1,write"
DEFAULT_CLIENT_SECRET = "test-secret-123"
INVALID_CLIENT_SECRET = "invalid-secret-xyz"
INVALID_SCOPE = "http://trace4.eu/invalid/scope,read"
EXCESSIVE_SCOPE = f"{DEFAULT_TEST_SCOPE} http://trace4.eu/ocs/unauthorized-resource,read"

# --- Base Test Class ---

"""Base class for authentication tests, providing common setup and helpers."""
class AuthTestBase:

    jwk_key = None 
    different_jwk_key = None
    admin_headers = None
    form_headers = None

    """Setup test class with common resources. Loads private key from .env."""
    @classmethod
    def setup_class(cls):

        # --- Check for required environment variables ---
        if not BEARER_TOKEN:
            pytest.fail(
                "ERROR: BEARER_TOKEN not found in environment variables (.env). "
                "Please run the key generation script first."
            )
        if BEARER_TOKEN == "<admin-bearer-token>": # Handle placeholder case
             pytest.skip("Placeholder BEARER_TOKEN found. Skipping tests.")

        if not TEST_SIGNING_PRIVATE_JWK_JSON:
            pytest.fail(
                "ERROR: TEST_SIGNING_PRIVATE_JWK not found in environment variables (.env). "
                "Please run the key generation script first to populate the .env file."
            )

        # --- Load Private Key from Environment Variable ---
        try:
            # Load the JWK object directly from the JSON string stored in the env var
            cls.jwk_key = jwk.JWK.from_json(TEST_SIGNING_PRIVATE_JWK_JSON)

            if not cls.jwk_key.has_private:
                pytest.fail(
                    "ERROR: Loaded JWK from TEST_SIGNING_PRIVATE_JWK env var "
                    "appears to be public only. Ensure the generation script "
                    "correctly saves the private key JSON to the .env file."
                )
            print(f"\nSuccessfully loaded private signing key (kid: {cls.jwk_key.get('kid')}) from .env")

        except json.JSONDecodeError:
            pytest.fail("ERROR: Failed to parse TEST_SIGNING_PRIVATE_JWK from .env as JSON.")
        except Exception as e:
             pytest.fail(f"ERROR: Failed to load JWK from TEST_SIGNING_PRIVATE_JWK: {e}")
        # --- End Key Loading ---


        # Generate a different key for negative tests (wrong signature)
        cls.different_jwk_key = jwk.JWK.generate(kty='EC', crv='P-256')
        # Ensure this key also has necessary metadata if your signing logic relies on it
        cls.different_jwk_key.update({'kid': 'test-key-different', 'use': 'sig', 'alg': 'ES256'})

        # Setup standard headers
        cls.admin_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {BEARER_TOKEN}'
        }
        cls.form_headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }

    # --- Helper Methods ---
    """Generates a unique ID string."""
    @staticmethod
    def _generate_unique_id(prefix="test"):
        return f"{prefix}-{uuid.uuid4().hex[:8]}"

    # --- Client Registration Helpers ---

    """Registers an OAuth client with various configurations (Class Method version)."""
    @classmethod
    def _register_client(cls, client_id, client_secret=None, grant_types=None,
                         token_auth_method="client_secret_basic", auth_alg=None,
                         jwks=None, access_token_strategy=None, extra_payload=None):
        payload = {"client_id": client_id}
        if client_secret: payload["client_secret"] = client_secret
        if grant_types: payload["grant_types"] = grant_types
        if token_auth_method: payload["token_endpoint_auth_method"] = token_auth_method
        if auth_alg: payload["token_endpoint_auth_signing_alg"] = auth_alg

        if jwks: payload["jwks"] = jwks
        if access_token_strategy: payload["access_token_strategy"] = access_token_strategy
        if extra_payload: payload.update(extra_payload)

        return requests.post(
            f"{ADMIN_URL}clients",
            headers=cls.admin_headers,
            data=json.dumps(payload)
        )

    """Instance method version of _register_client"""
    def _register_client_instance(self, client_id, client_secret=None, grant_types=None,
                         token_auth_method="client_secret_basic", auth_alg=None,
                         jwks=None, access_token_strategy=None, extra_payload=None):
        payload = {"client_id": client_id}
        if client_secret: payload["client_secret"] = client_secret
        if grant_types: payload["grant_types"] = grant_types
        if token_auth_method: payload["token_endpoint_auth_method"] = token_auth_method
        if auth_alg: payload["token_endpoint_auth_signing_alg"] = auth_alg
        if jwks: payload["jwks"] = jwks
        if access_token_strategy: payload["access_token_strategy"] = access_token_strategy
        if extra_payload: payload.update(extra_payload)

        return requests.post(
            f"{ADMIN_URL}clients",
            headers=self.admin_headers,
            data=json.dumps(payload)
        )
     
    """Registers a simple client with secret (Class method version)"""
    @classmethod
    def _register_client_with_secret_class(cls, client_id, client_secret):
         return cls._register_client(
            client_id=client_id,
            client_secret=client_secret,
            grant_types=["urn:ietf:params:oauth:grant-type:jwt-bearer"] 
        )

    """Registers a simple client with secret (Instance method version)"""
    def _register_client_with_secret(self, client_id, client_secret):
        return self._register_client_instance(
            client_id=client_id,
            client_secret=client_secret,
            grant_types=["urn:ietf:params:oauth:grant-type:jwt-bearer"]
        )

    # --- Scope Configuration Helper ---
    """Configures client scope via PATCH (Class method version)"""
    @classmethod
    def _configure_client_scope_class(cls, client_id, scope):
        payload = [{"op": "replace", "path": "/scope", "value": scope}]
        return requests.patch(
            f"{ADMIN_URL}clients/{client_id}",
            headers=cls.admin_headers,
            data=json.dumps(payload)
        )
    
    """Configures client scope via PATCH (Instance method version)"""
    def _configure_client_scope(self, client_id, scope):
         payload = [{"op": "replace", "path": "/scope", "value": scope}]
         return requests.patch(
            f"{ADMIN_URL}clients/{client_id}",
            headers=self.admin_headers,
            data=json.dumps(payload)
        )

    # --- User Trust Grant (Issuer) Registration Helper ---
    """Registers a user/issuer JWT Bearer grant (Class method version). Uses cls.jwk_key."""
    @classmethod
    def _register_user_key_grant_class(cls, issuer, subject, scope=None, expires_at="2029-12-31T23:59:59Z"):
        if not cls.jwk_key: pytest.fail("Setup Error: cls.jwk_key not initialized.")

        reg_scope = scope or DEFAULT_TEST_SCOPE
        payload = {
            "expires_at": expires_at, "issuer": issuer, "subject": subject,
            "allow_any_subject": False, 
            "token_endpoint_auth_signing_alg": "ES256",
            "jwk": cls.jwk_key.export_public(as_dict=True),
            "scope": reg_scope.split()
        }
        return requests.post(
            f"{ADMIN_URL}trust/grants/jwt-bearer/issuers",
            headers=cls.admin_headers,
            data=json.dumps(payload)
        )

    """Registers a user/issuer JWT Bearer grant (Instance method version). Uses key_to_use or self.jwk_key."""
    def _register_user_key_grant(self, issuer, subject, key_to_use=None, scope=None, expires_at="2029-12-31T23:59:59Z"):
         signing_key = key_to_use or self.jwk_key
         if not signing_key: pytest.fail("Runtime Error: No valid key provided/available.")

         reg_scope = scope or DEFAULT_TEST_SCOPE
         payload = {
            "expires_at": expires_at, "issuer": issuer, "subject": subject,
            "allow_any_subject": False,
            "token_endpoint_auth_signing_alg": "ES256",
            "jwk": signing_key.export_public(as_dict=True),
            "scope": reg_scope.split()
         }
         return requests.post(
            f"{ADMIN_URL}trust/grants/jwt-bearer/issuers",
            headers=self.admin_headers,
            data=json.dumps(payload)
        )

    # --- Client Registration using private_key_jwt ---
    """Registers a client using private_key_jwt authentication."""
    def _register_jwt_client(self, client_id):
        if not self.jwk_key: pytest.fail("Runtime Error: self.jwk_key not available.")
        # Register the client and provide its PUBLIC key so the server can verify assertions
        return self._register_client_instance(
            client_id=client_id,
            grant_types=["client_credentials"],
            token_auth_method="private_key_jwt",
            auth_alg="ES256", 
            jwks={"keys": [self.jwk_key.export_public(as_dict=True)]}
        )

    # --- Client Registration requesting JWT Access Tokens ---
    """Registers a client using client_secret_basic but requesting JWT access tokens."""
    def _register_client_with_jwt_strategy(self, client_id, client_secret):
        return self._register_client_instance(
            client_id=client_id,
            client_secret=client_secret,
            grant_types=["urn:ietf:params:oauth:grant-type:jwt-bearer"],
            access_token_strategy="jwt"
        )

    # --- JWT Creation Helpers ---
    """Core JWT creation and signing function."""
    def _create_jwt(self, issuer, subject, audience, key_to_use, exp_offset_seconds=600, custom_claims=None):
        # Ensure the key passed has private parts needed for signing
        if not key_to_use or not key_to_use.has_private:
            key_id_str = key_to_use.get('kid') if key_to_use else 'None'
            pytest.fail(f"Runtime Error in _create_jwt: Attempted to sign JWT with invalid or public-only key (kid: {key_id_str})")

        # Get algorithm and key ID from the key object itself if available
        alg = key_to_use.get('alg', 'ES256') # Default to ES256 if not in key
        kid = key_to_use.get('kid')

        jwt_header = {"typ": "jwt", "alg": alg}
        if kid: jwt_header["kid"] = kid

        now = int(time.time())
        jwt_claims = {
            "iss": issuer, "sub": subject, "aud": audience,
            "jti": str(uuid.uuid4()),
            "iat": now, 
            "nbf": now,
            "exp": now + exp_offset_seconds
        }
        if custom_claims: jwt_claims.update(custom_claims)

        # Create and sign the token
        token = jwt.JWT(header=jwt_header, claims=jwt_claims)
        token.make_signed_token(key_to_use) # This requires the private key in key_to_use
        return token.serialize()

    """Creates a JWT assertion for private_key_jwt client authentication."""
    def _create_client_jwt_assertion(self, client_id, key_to_use=None, exp_offset_seconds=600, audience=None, issuer=None):
        signing_key = key_to_use or self.jwk_key 
        aud = audience or TOKEN_URL 
        iss = issuer or client_id 
        sub = client_id 
        return self._create_jwt(iss, sub, aud, signing_key, exp_offset_seconds)

    """Creates a JWT assertion for the jwt-bearer grant type."""
    def _create_user_jwt_grant(self, issuer, subject, key_to_use=None, exp_offset_seconds=600, audience=None, custom_claims=None):
        signing_key = key_to_use or self.jwk_key 
        aud = audience or TOKEN_URL 
        return self._create_jwt(issuer, subject, aud, signing_key, exp_offset_seconds, custom_claims)

    # --- Token Request Helpers ---
    """Requests a token using client_credentials grant and private_key_jwt auth."""
    def _get_token_client_credentials(self, client_id, assertion, scope):
        payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
            "scope": scope
        }
        return requests.post(TOKEN_URL, headers=self.form_headers, data=payload)

    """Requests a token using jwt-bearer grant type and client_secret_basic auth."""
    def _get_token_jwt_bearer_grant(self, client_id, client_secret, assertion, scope):
        auth_header = f"{client_id}:{client_secret}"
        encoded_auth = base64.b64encode(auth_header.encode()).decode()
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {encoded_auth}'
        }
        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion, 
            "scope": scope
        }
        return requests.post(TOKEN_URL, headers=headers, data=payload)

    # --- Token Introspection Helper ---
    """Introspects a token using the admin endpoint."""
    def _introspect_token(self, token):
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Bearer {BEARER_TOKEN}' 
        }
        payload = {"token": token}
        introspection_url = f"{ADMIN_URL}oauth2/introspect"
        return requests.post(introspection_url, headers=headers, data=payload)


    # --- Misc Helpers ---
    """Attempts to tamper with the payload of a JWT (invalidates signature)."""
    def _tamper_with_jwt(self, valid_jwt):
        parts = valid_jwt.split('.')
        if len(parts) != 3: return valid_jwt 
        try:
            # Decode payload
            padded_payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
            decoded_bytes = base64.urlsafe_b64decode(padded_payload)
            decoded_str = decoded_bytes.decode('utf-8')

            # Modify payload slightly (e.g., change last character)
            if len(decoded_str) > 0:
                 original_char_ord = ord(decoded_str[-1])
                 tampered_char = chr((original_char_ord + 1 - 32) % (127 - 32) + 32)
                 modified_str = decoded_str[:-1] + tampered_char

                 # Re-encode payload
                 encoded_bytes = modified_str.encode('utf-8')
                 tampered_payload_encoded = base64.urlsafe_b64encode(encoded_bytes).decode('utf-8').rstrip('=')

                 # Reassemble with original header/signature but tampered payload
                 return f"{parts[0]}.{tampered_payload_encoded}.{parts[2]}"
            else:
                 return valid_jwt
        except Exception as e:
             print(f"Warning: Error during JWT tampering: {e}")
             return valid_jwt 


# --- Positive Test Scenarios ---
@allure.epic("TRACE4EU Authorization and Authentication component")
@allure.feature("Positive Scenarios")
class TestAuthServicePositive(AuthTestBase):

    @allure.title("Scenario 1: Client application authorization with JWT authentication")
    @allure.description("Verifies that a client can register with JWT authentication, configure a scope, and obtain a valid access token using private_key_jwt authentication")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_scenario1_client_auth_with_jwt(self):
        print("\n\n=== Running Scenario 1: Client with JWT Auth (private_key_jwt) ===")
        test_client_id = self._generate_unique_id("pos-s1-jwt")

        # Register client providing its PUBLIC key
        client_reg = self._register_jwt_client(test_client_id)
        assert client_reg.status_code in [200, 201], f"Failed Sc1 Reg: {client_reg.text}"
        print(f"Step 1: Client registered with private_key_jwt auth (ID: {test_client_id})")

        scope_update = self._configure_client_scope(test_client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200, f"Failed Sc1 Scope: {scope_update.text}"
        print(f"Step 2: Client scope configured: {DEFAULT_TEST_SCOPE}")

        # Create assertion SIGNED WITH THE CLIENT'S PRIVATE KEY
        assertion = self._create_client_jwt_assertion(test_client_id) # Uses self.jwk_key by default

        # Request token using the signed assertion for authentication
        token_res = self._get_token_client_credentials(test_client_id, assertion, DEFAULT_TEST_SCOPE)
        assert token_res.status_code == 200, f"Failed Sc1 Token Req: {token_res.text}"
        token_data = token_res.json()
        access_token = token_data.get("access_token")
        assert access_token, "No access token returned in Sc1"
        print(f"Step 3: Access token obtained using client credentials grant and JWT assertion")

        introspect_res = self._introspect_token(access_token)
        assert introspect_res.status_code == 200, f"Failed Sc1 Introspect: {introspect_res.text}"
        introspect_data = introspect_res.json()
        assert introspect_data.get("active") is True, "Token not active in Sc1"
        assert introspect_data.get("client_id") == test_client_id, "Client ID mismatch in Sc1"
        print(f"Step 4: Token introspection successful and active")

    @allure.title("Scenario 2: Delegation of authorization rights to a user")
    @allure.description("Verifies that a user can delegate authorization rights to a client, which can request an access token by presenting a user-signed JWT authorization grant")
    def test_scenario2_user_delegated_auth(self):
        print("\n\n=== Running Scenario 2: User Delegated Auth (jwt-bearer grant) ===")
        test_client_id = self._generate_unique_id("pos-s2-dlg")
        user_issuer = self._generate_unique_id("pos-s2-usriss")
        user_subject = self._generate_unique_id("pos-s2-usrsubj") # Can be different from issuer

        # Register the user's grant: associate issuer/subject with their PUBLIC key
        user_reg = self._register_user_key_grant(user_issuer, user_subject, scope=DEFAULT_TEST_SCOPE) # Uses self.jwk_key by default
        assert user_reg.status_code in [200, 201], f"Failed Sc2 UserGrantReg: {user_reg.text}"
        print(f"Step 1: User grant registered (Issuer: {user_issuer}, Subject: {user_subject})")

        # Register the client that will request tokens on behalf of the user
        client_reg = self._register_client_with_secret(test_client_id, DEFAULT_CLIENT_SECRET)
        assert client_reg.status_code in [200, 201], f"Failed Sc2 ClientReg: {client_reg.text}"
        print(f"Step 2: Client registered (ID: {test_client_id})")

        # Configure the client's allowed scopes (must include scopes requested later)
        scope_update = self._configure_client_scope(test_client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200 , f"Failed Sc2 ScopeConf: {scope_update.text}"
        print(f"Step 2b: Client scope configured: {DEFAULT_TEST_SCOPE}")

        # Create the JWT grant assertion SIGNED WITH THE USER'S PRIVATE KEY
        auth_grant = self._create_user_jwt_grant(user_issuer, user_subject) # Uses self.jwk_key by default
        print(f"Step 3: JWT authorization grant assertion created (signed by user key)")

        # Client requests token using its credentials and the user's grant assertion
        token_res = self._get_token_jwt_bearer_grant(test_client_id, DEFAULT_CLIENT_SECRET, auth_grant, DEFAULT_TEST_SCOPE)
        assert token_res.status_code == 200, f"Failed Sc2 Token Req: {token_res.text}"
        token_data = token_res.json()
        access_token = token_data.get("access_token")
        assert access_token, "No access token returned in Sc2"
        print(f"Step 4: Access token obtained via jwt-bearer grant")

        introspect_res = self._introspect_token(access_token)
        assert introspect_res.status_code == 200, f"Failed Sc2 Introspect: {introspect_res.text}"
        introspect_data = introspect_res.json()
        assert introspect_data.get("active") is True, "Token not active in Sc2"
        # Check that the token carries user context (sub) and client context (client_id)
        assert introspect_data.get("sub") == user_subject, "Subject mismatch in Sc2 token"
        assert introspect_data.get("client_id") == test_client_id, "Client ID mismatch in Sc2 token"
        print(f"Step 5: Token introspection successful. User Sub: {introspect_data.get('sub')}, Client ID: {introspect_data.get('client_id')}")

    @allure.title("Scenario 3: Issue JWT access tokens")
    @allure.description("Verifies that the system can issue access tokens in JWT format when configured with the JWT access token strategy, maintaining the correct format and required structure")
    def test_scenario3_jwt_access_token(self):
        print("\n\n=== Running Scenario 3: JWT Access Token Strategy ===")
        test_client_id = self._generate_unique_id("pos-s3-jwt")
        user_issuer_subject = self._generate_unique_id("pos-s3-usr") # Simple case: issuer == subject

        # Register user grant (as in Scenario 2)
        user_reg = self._register_user_key_grant(user_issuer_subject, user_issuer_subject, scope=DEFAULT_TEST_SCOPE)
        assert user_reg.status_code in [200, 201], f"Failed Sc3 UserGrantReg: {user_reg.text}"
        print(f"Step 1: User grant registered (Issuer/Subject: {user_issuer_subject})")

        # Register client, specifically requesting JWT access token strategy
        client_reg = self._register_client_with_jwt_strategy(test_client_id, DEFAULT_CLIENT_SECRET)
        assert client_reg.status_code in [200, 201], f"Failed Sc3 ClientReg: {client_reg.text}"
        print(f"Step 2: Client registered requesting JWT strategy (ID: {test_client_id})")

        # Configure client scope
        scope_update = self._configure_client_scope(test_client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200 , f"Failed Sc3 ScopeConf: {scope_update.text}"
        print(f"Step 2b: Client scope configured: {DEFAULT_TEST_SCOPE}")

        # Create user grant assertion (signed with user key)
        auth_grant = self._create_user_jwt_grant(user_issuer_subject, user_issuer_subject)
        print(f"Step 3: JWT authorization grant assertion created")

        # Request token
        token_res = self._get_token_jwt_bearer_grant(test_client_id, DEFAULT_CLIENT_SECRET, auth_grant, DEFAULT_TEST_SCOPE)
        assert token_res.status_code == 200, f"Failed Sc3 Token Req: {token_res.text}"
        token_data = token_res.json()
        access_token = token_data.get("access_token")
        assert access_token, "No access token returned in Sc3"
        print(f"Step 4: Access token obtained via user grant")

        # Validate the token format IS a JWT
        assert '.' in access_token, "Access token is not in JWT format (no dots)"
        token_parts = access_token.split('.')
        assert len(token_parts) == 3, f"Access token is not JWT format (expected 3 parts, got {len(token_parts)})"
        print(f"Step 5: Access token appears to be a valid JWT format.")

# --- Negative Test Scenarios ---
# (Using instance methods like self._register_client_instance for actions within tests)
@allure.epic("TRACE4EU Authorization and Authentication component")
@allure.feature("Negative Tests Scenario 1")
class TestAuthServiceNegativeScenario1(AuthTestBase):
    """Negative tests focusing on Scenario 1: Client Auth with JWT (private_key_jwt)"""

    @allure.title("Negative test - Invalid client registration parameters")
    @allure.description("Verifies that client registration fails with invalid parameters such as improper redirect URIs")
    def test_neg_s1_invalid_client_registration_params(self):
        print("\n\n=== Running Neg Sc1: Invalid Client Registration Params ===")
        client_id = self._generate_unique_id("neg-s1-regbad")
        # Example invalid parameter (depends on server validation rules)
        extra = {"redirect_uris": ["not a valid uri"]}
        response = self._register_client_instance(
            client_id=client_id,
            grant_types=["client_credentials"],
            token_auth_method="private_key_jwt",
            auth_alg="ES256",
            jwks={"keys": [self.jwk_key.export_public(as_dict=True)]},
            extra_payload=extra
        )
        assert response.status_code not in [200, 201], f"Neg Sc1 Reg Params: Expected failure, got {response.status_code}. Body: {response.text}"
        print(f"Neg Sc1 Reg Params: Registration failed as expected ({response.status_code})")

    @allure.title("Negative test - Unsupported signing algorithm")
    @allure.description("Ensures the system rejects client registrations with unsupported JWT signing algorithms")
    def test_neg_s1_unsupported_algorithm(self):
        print("\n\n=== Running Neg Sc1: Unsupported Client Auth Algorithm ===")
        client_id = self._generate_unique_id("neg-s1-algo")
        # Registering with an unsupported algorithm (e.g., HS512 if only ES256 is allowed)
        response = self._register_client_instance(
            client_id=client_id,
            grant_types=["client_credentials"],
            token_auth_method="private_key_jwt",
            auth_alg="HS512", # Assume HS512 is not supported/configured
            jwks={"keys": [self.jwk_key.export_public(as_dict=True)]} # Key type might also mismatch alg
        )
        assert response.status_code not in [200, 201], f"Neg Sc1 Algo: Expected failure, got {response.status_code}. Body: {response.text}"
        print(f"Neg Sc1 Algo: Registration or subsequent token request should fail ({response.status_code})")

    @allure.title("Negative test - Expired JWT assertion")
    @allure.description("Confirms that token requests with expired JWT client assertions are propery rejected")
    def test_neg_s1_expired_jwt_assertion(self):
        print("\n\n=== Running Neg Sc1: Expired Client JWT Assertion ===")
        client_id = self._generate_unique_id("neg-s1-expjwt")
        # Setup: Register a valid client first
        client_reg = self._register_jwt_client(client_id)
        assert client_reg.status_code in [200, 201], f"Neg Sc1 ExpJWT Setup Fail Reg: {client_reg.text}"
        scope_update = self._configure_client_scope(client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200, f"Neg Sc1 ExpJWT Setup Fail Scope: {scope_update.text}"

        # Create an assertion that has already expired
        expired_assertion = self._create_client_jwt_assertion(client_id, exp_offset_seconds=-600) # Expired 10 mins ago

        # Attempt token request with the expired assertion
        token_res = self._get_token_client_credentials(client_id, expired_assertion, DEFAULT_TEST_SCOPE)
        assert token_res.status_code not in [200], f"Neg Sc1 ExpJWT: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc1 ExpJWT: Token request failed due to expired assertion as expected ({token_res.status_code})")
    
    @allure.title("Negative test - Invalid audience in JWT assertion")
    @allure.description("Verifies that JWT assertions with incorrect audience claims are rejected during token requests")
    def test_neg_s1_invalid_audience(self):
        print("\n\n=== Running Neg Sc1: Invalid Audience in Client Assertion ===")
        client_id = self._generate_unique_id("neg-s1-aud")
        # Setup: Register client
        client_reg = self._register_jwt_client(client_id)
        assert client_reg.status_code in [200, 201], f"Neg Sc1 Aud Setup Fail Reg: {client_reg.text}"
        scope_update = self._configure_client_scope(client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200, f"Neg Sc1 Aud Setup Fail Scope: {scope_update.text}"

        # Create assertion with the wrong audience (should be TOKEN_URL)
        invalid_aud_assertion = self._create_client_jwt_assertion(client_id, audience="https://invalid.audience.com")

        # Attempt token request
        token_res = self._get_token_client_credentials(client_id, invalid_aud_assertion, DEFAULT_TEST_SCOPE)
        assert token_res.status_code not in [200], f"Neg Sc1 Aud: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc1 Aud: Token request failed due to invalid audience as expected ({token_res.status_code})")

    @allure.title("Negative test - Wrong signing key")
    @allure.description("Ensures token requests fail when using a different signing key than the one registered")
    def test_neg_s1_wrong_signing_key(self):
        print("\n\n=== Running Neg Sc1: Client Assertion Signed with Wrong Key ===")
        client_id = self._generate_unique_id("neg-s1-key")
        # Setup: Register client with the PUBLIC part of self.jwk_key
        client_reg = self._register_jwt_client(client_id)
        assert client_reg.status_code in [200, 201], f"Neg Sc1 Key Setup Fail Reg: {client_reg.text}"
        scope_update = self._configure_client_scope(client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200, f"Neg Sc1 Key Setup Fail Scope: {scope_update.text}"

        # Create assertion signed with a DIFFERENT private key (self.different_jwk_key)
        wrong_key_assertion = self._create_client_jwt_assertion(client_id, key_to_use=self.different_jwk_key)

        # Attempt token request - server should fail validation as signature doesn't match registered key
        token_res = self._get_token_client_credentials(client_id, wrong_key_assertion, DEFAULT_TEST_SCOPE)
        assert token_res.status_code not in [200], f"Neg Sc1 Key: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc1 Key: Token request failed due to signature mismatch as expected ({token_res.status_code})")

    @allure.title("Negative test - Invalid scope request")
    @allure.description("Confirms that requests for unauthorized scopes either fail or return tokens with reduced permissions")
    def test_neg_s1_invalid_scope_request(self):
        print("\n\n=== Running Neg Sc1: Client Requesting Invalid Scope ===")
        client_id = self._generate_unique_id("neg-s1-scope")
        # Setup: Register client and configure it ONLY for DEFAULT_TEST_SCOPE
        client_reg = self._register_jwt_client(client_id)
        assert client_reg.status_code in [200, 201], f"Neg Sc1 Scope Setup Fail Reg: {client_reg.text}"
        scope_update = self._configure_client_scope(client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200, f"Neg Sc1 Scope Setup Fail Scope: {scope_update.text}"

        # Create a valid assertion
        assertion = self._create_client_jwt_assertion(client_id)

        # Attempt token request asking for an INVALID scope not configured for the client
        token_res = self._get_token_client_credentials(client_id, assertion, INVALID_SCOPE)

        if token_res.status_code == 200:
            # If it succeeded, check that the granted scope does NOT include the invalid one
            token_data = token_res.json()
            granted_scope = token_data.get("scope", "")
            assert INVALID_SCOPE not in granted_scope.split(), f"Neg Sc1 Scope: Invalid scope '{INVALID_SCOPE}' was granted unexpectedly. Granted: '{granted_scope}'"
            print(f"Neg Sc1 Scope: Token granted but invalid scope was correctly omitted. Granted: '{granted_scope}' (Status: {token_res.status_code})")
        else:
             # If it failed (e.g., 400 Bad Request), that's also acceptable.
             assert token_res.status_code not in [200], f"Neg Sc1 Scope: Expected failure or reduced scope, got {token_res.status_code}. Body: {token_res.text}"
             print(f"Neg Sc1 Scope: Token request failed due to invalid scope request as expected ({token_res.status_code})")
    
    @allure.title("Negative test - Client ID issuer mismatch")
    @allure.description("Verifies that JWT assertions with issuers not matching the client ID are rejected")
    def test_neg_s1_client_id_issuer_mismatch(self):
        print("\n\n=== Running Neg Sc1: Client ID / Issuer Mismatch in Assertion ===")
        client_id = self._generate_unique_id("neg-s1-iss")
        # Setup: Register client
        client_reg = self._register_jwt_client(client_id)
        assert client_reg.status_code in [200, 201], f"Neg Sc1 ID/Iss Setup Fail Reg: {client_reg.text}"
        scope_update = self._configure_client_scope(client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200, f"Neg Sc1 ID/Iss Setup Fail Scope: {scope_update.text}"

        # Create assertion where the 'iss' claim does NOT match the client_id
        wrong_issuer = f"wrong-issuer-{uuid.uuid4().hex[:8]}"
        mismatch_assertion = self._create_client_jwt_assertion(client_id, issuer=wrong_issuer)

        # Attempt token request
        token_res = self._get_token_client_credentials(client_id, mismatch_assertion, DEFAULT_TEST_SCOPE)
        assert token_res.status_code not in [200], f"Neg Sc1 ID/Iss: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc1 ID/Iss: Token request failed due to issuer/client_id mismatch as expected ({token_res.status_code})")

    @allure.title("Negative test - Tampered JWT assertion")
    @allure.description("Ensures that modified or tampered JWT assertions fail signature validation and are rejected")
    def test_neg_s1_tampered_jwt_assertion(self):
        print("\n\n=== Running Neg Sc1: Tampered Client JWT Assertion ===")
        client_id = self._generate_unique_id("neg-s1-tamper")
        # Setup: Register client
        client_reg = self._register_jwt_client(client_id)
        assert client_reg.status_code in [200, 201], f"Neg Sc1 Tamper Setup Fail Reg: {client_reg.text}"
        scope_update = self._configure_client_scope(client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200, f"Neg Sc1 Tamper Setup Fail Scope: {scope_update.text}"

        # Create a valid assertion
        valid_assertion = self._create_client_jwt_assertion(client_id)
        # Tamper with the payload (this invalidates the signature)
        tampered_assertion = self._tamper_with_jwt(valid_assertion)
        assert valid_assertion != tampered_assertion, "Tampering failed to modify JWT for Neg Sc1"

        # Attempt token request with the tampered assertion
        token_res = self._get_token_client_credentials(client_id, tampered_assertion, DEFAULT_TEST_SCOPE)
        assert token_res.status_code not in [200], f"Neg Sc1 Tamper: Expected failure due to invalid signature, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc1 Tamper: Token request failed due to tampered assertion (invalid signature) as expected ({token_res.status_code})")

@allure.epic("TRACE4EU Authorization and Authentication component")
@allure.feature("Negative Tests Scenario 2")
class TestAuthServiceNegativeScenario2(AuthTestBase):
    """Negative tests focusing on Scenario 2: User Delegated Auth (jwt-bearer grant)"""

    # Use class setup for shared resources specific to these tests
    test_client_id_s2 = None
    user_issuer_s2 = None
    user_subject_s2 = None

    @classmethod
    def setup_class(cls):
        """Setup specific resources for Scenario 2 negative tests"""
        super().setup_class() # Call base setup first (loads keys, headers etc)

        # Generate unique IDs for this suite
        cls.test_client_id_s2 = cls._generate_unique_id("neg-s2-cli")
        cls.user_issuer_s2 = cls._generate_unique_id("neg-s2-usriss")
        cls.user_subject_s2 = cls._generate_unique_id("neg-s2-usrsubj")

        # --- Setup required registrations using @classmethod helpers ---
        # Register the user grant (associating issuer/subject with the public key)
        user_reg = cls._register_user_key_grant_class(
            cls.user_issuer_s2, cls.user_subject_s2, scope=DEFAULT_TEST_SCOPE
        )
        if user_reg.status_code not in [200, 201]:
            pytest.fail(f"Neg Sc2 Setup Error: Failed to register user grant: {user_reg.status_code} {user_reg.text}")

        # Register the client that will make the requests
        client_reg = cls._register_client_with_secret_class(
            cls.test_client_id_s2, DEFAULT_CLIENT_SECRET
        )
        if client_reg.status_code not in [200, 201]:
             pytest.fail(f"Neg Sc2 Setup Error: Failed to register client: {client_reg.status_code} {client_reg.text}")

        # Configure the client's scope
        scope_update = cls._configure_client_scope_class(
            cls.test_client_id_s2, DEFAULT_TEST_SCOPE
        )
        if scope_update.status_code != 200:
             # Non-fatal warning, but might indicate issues
             print(f"Warning Neg Sc2 Setup: Failed scope config {scope_update.status_code} {scope_update.text}")
        print(f"\nNeg Sc2 Setup Complete: Client={cls.test_client_id_s2}, Issuer={cls.user_issuer_s2}, Subject={cls.user_subject_s2}")


    # Test methods use instance methods (self._method_name) as usual
    @allure.title("Negative test - Expired JWT grant assertion")
    @allure.description("Verifies that authorization servers reject JWT authorization grants that have expired")
    def test_neg_s2_expired_jwt_grant_assertion(self):
        print("\n\n=== Running Neg Sc2: Expired JWT Grant Assertion ===")
        # Create an expired grant assertion (signed with user's key)
        expired_grant = self._create_user_jwt_grant(
            self.user_issuer_s2, self.user_subject_s2, exp_offset_seconds=-600 # Expired
        )
        # Client attempts to get token using the expired grant
        token_res = self._get_token_jwt_bearer_grant(
            self.test_client_id_s2, DEFAULT_CLIENT_SECRET, expired_grant, DEFAULT_TEST_SCOPE
        )
        assert token_res.status_code != 200, f"Neg Sc2 ExpGrant: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc2 ExpGrant: Token request failed due to expired grant assertion as expected ({token_res.status_code})")

    @allure.title("Negative test - Invalid client secret")
    @allure.description("Confirms that token requests fail when clients provide incorrect client secrets")
    def test_neg_s2_invalid_client_secret(self):
        print("\n\n=== Running Neg Sc2: Invalid Client Secret ===")
        # Create a valid grant assertion
        valid_grant = self._create_user_jwt_grant(self.user_issuer_s2, self.user_subject_s2)
        # Client attempts to get token using the WRONG secret for authentication
        token_res = self._get_token_jwt_bearer_grant(
            self.test_client_id_s2, INVALID_CLIENT_SECRET, valid_grant, DEFAULT_TEST_SCOPE
        )
        assert token_res.status_code != 200, f"Neg Sc2 BadSecret: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        # This failure is due to client authentication (Basic Auth), not the grant itself
        print(f"Neg Sc2 BadSecret: Token request failed due to invalid client secret as expected ({token_res.status_code})")

    @allure.title("Negative test - Mismatched subject in grant")
    @allure.description("Ensures the system rejects JWT grants where the subject doesn't match the registered subject")
    def test_neg_s2_mismatched_subject_in_grant(self):
        print("\n\n=== Running Neg Sc2: Mismatched Subject in Grant Assertion ===")
        # Create grant assertion with the correct issuer BUT the wrong subject
        # (subject doesn't match the one registered for this issuer grant)
        wrong_subject = f"wrong-subject-{uuid.uuid4().hex[:8]}"
        mismatched_grant = self._create_user_jwt_grant(self.user_issuer_s2, wrong_subject)
        # Client attempts token request
        token_res = self._get_token_jwt_bearer_grant(
            self.test_client_id_s2, DEFAULT_CLIENT_SECRET, mismatched_grant, DEFAULT_TEST_SCOPE
        )
        assert token_res.status_code != 200, f"Neg Sc2 BadSubj: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc2 BadSubj: Token request failed due to subject mismatch in grant as expected ({token_res.status_code})")

    @allure.title("Negative test - Invalid grant signature")
    @allure.description("Verifies that JWT grants with invalid signatures are properly rejected")
    def test_neg_s2_invalid_grant_signature(self):
        print("\n\n=== Running Neg Sc2: Invalid Signature on Grant Assertion ===")
        # Create grant assertion signed with the WRONG private key
        invalid_sig_grant = self._create_user_jwt_grant(
            self.user_issuer_s2, self.user_subject_s2, key_to_use=self.different_jwk_key
        )
        # Client attempts token request
        token_res = self._get_token_jwt_bearer_grant(
            self.test_client_id_s2, DEFAULT_CLIENT_SECRET, invalid_sig_grant, DEFAULT_TEST_SCOPE
        )
        assert token_res.status_code != 200, f"Neg Sc2 BadSig: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc2 BadSig: Token request failed due to invalid grant signature as expected ({token_res.status_code})")
    
    @allure.title("Negative test - Tampered grant assertion")
    @allure.description("Verifies token request fails when the jwt-bearer grant assertion's payload is modified, invalidating its signature")   
    def test_neg_s2_tampered_grant_assertion(self):
        print("\n\n=== Running Neg Sc2: Tampered Grant Assertion ===")
        # Create a valid grant
        valid_grant = self._create_user_jwt_grant(self.user_issuer_s2, self.user_subject_s2)
        # Tamper with it (invalidates signature)
        tampered_grant = self._tamper_with_jwt(valid_grant)
        assert valid_grant != tampered_grant, "Tampering failed for Neg Sc2 Grant"
        # Client attempts token request with tampered grant
        token_res = self._get_token_jwt_bearer_grant(
            self.test_client_id_s2, DEFAULT_CLIENT_SECRET, tampered_grant, DEFAULT_TEST_SCOPE
        )
        assert token_res.status_code != 200, f"Neg Sc2 TamperGrant: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc2 TamperGrant: Token request failed due to tampered grant (invalid signature) as expected ({token_res.status_code})")

    @allure.title("Negative test - Invalid audience in grant")
    @allure.description("Confirms that JWT grants with incorrect audience claims are rejected")
    def test_neg_s2_invalid_audience_in_grant(self):
        print("\n\n=== Running Neg Sc2: Invalid Audience in Grant Assertion ===")
        # Create grant assertion with the wrong audience
        invalid_aud_grant = self._create_user_jwt_grant(
            self.user_issuer_s2, self.user_subject_s2, audience="https://wrong.audience.com"
        )
        # Client attempts token request
        token_res = self._get_token_jwt_bearer_grant(
            self.test_client_id_s2, DEFAULT_CLIENT_SECRET, invalid_aud_grant, DEFAULT_TEST_SCOPE
        )
        assert token_res.status_code != 200, f"Neg Sc2 BadAud: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc2 BadAud: Token request failed due to invalid audience in grant as expected ({token_res.status_code})")

    @allure.title("Negative test - Request excessive scope")
    @allure.description("Verifies that requests for scopes beyond what's authorized either fail or return reduced scope tokens")
    def test_neg_s2_request_excessive_scope(self):
        print("\n\n=== Running Neg Sc2: Client Requesting Excessive Scope ===")
        # Create a valid grant assertion
        valid_grant = self._create_user_jwt_grant(self.user_issuer_s2, self.user_subject_s2)
        # Client attempts token request asking for MORE scope than configured/granted
        token_res = self._get_token_jwt_bearer_grant(
            self.test_client_id_s2, DEFAULT_CLIENT_SECRET, valid_grant, EXCESSIVE_SCOPE
        )
        # Expected: Fail or succeed with reduced scope
        if token_res.status_code == 200:
            granted_scope = token_res.json().get("scope", "")
            excess_part = "http://trace4.eu/ocs/unauthorized-resource,read"
            assert excess_part not in granted_scope.split(), f"Neg Sc2 ExScope: Excessive scope '{excess_part}' granted unexpectedly: {granted_scope}"
            print(f"Neg Sc2 ExScope: Token granted with reduced scope '{granted_scope}' as expected.")
        else:
            assert token_res.status_code != 200, f"Neg Sc2 ExScope: Expected failure or reduced scope, got {token_res.status_code}. Body: {token_res.text}"
            print(f"Neg Sc2 ExScope: Token request failed due to excessive scope request as expected ({token_res.status_code})")

    @allure.title("Negative test - Unregistered issuer in grant")
    @allure.description("Ensures the system rejects JWT grants from issuers that aren't registered in the system")
    def test_neg_s2_unregistered_issuer_in_grant(self):
        print("\n\n=== Running Neg Sc2: Unregistered Issuer in Grant Assertion ===")
        # Use an issuer for which no grant has been registered
        unregistered_issuer = f"unregistered-issuer-{uuid.uuid4().hex[:8]}"
        unregistered_grant = self._create_user_jwt_grant(unregistered_issuer, self.user_subject_s2) # Subject might be valid, but issuer isn't registered
        # Client attempts token request
        token_res = self._get_token_jwt_bearer_grant(
            self.test_client_id_s2, DEFAULT_CLIENT_SECRET, unregistered_grant, DEFAULT_TEST_SCOPE
        )
        assert token_res.status_code != 200, f"Neg Sc2 UnregIss: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc2 UnregIss: Token request failed due to unregistered issuer in grant as expected ({token_res.status_code})")


# --- Negative Tests for Scenario 3 (JWT Access Token Strategy) ---
@allure.epic("TRACE4EU Authorization and Authentication component")
@allure.feature("Negative Tests Scenario 3")
class TestAuthServiceNegativeScenario3(AuthTestBase):
    """Negative tests focusing on Scenario 3: JWT Access Token Strategy"""

    @allure.title("Negative test - Expired JWT grant")
    @allure.description("Verifies that requests for JWT access tokens with expired authorization grants are rejected")
    def test_neg_s3_expired_jwt_grant(self):
        print("\n\n=== Running Neg Sc3: Expired JWT Grant (JWT Token Strategy) ===")
        # Setup for this specific test
        client_id = self._generate_unique_id("neg-s3-expcli")
        issuer_subject = self._generate_unique_id("neg-s3-expusr")
        user_reg = self._register_user_key_grant(issuer_subject, issuer_subject, scope=DEFAULT_TEST_SCOPE)
        assert user_reg.status_code in [200, 201], f"Neg Sc3 ExpGrant Setup Fail UserReg: {user_reg.text}"
        client_reg = self._register_client_with_jwt_strategy(client_id, DEFAULT_CLIENT_SECRET)
        assert client_reg.status_code in [200, 201], f"Neg Sc3 ExpGrant Setup Fail ClientReg: {client_reg.text}"
        scope_update = self._configure_client_scope(client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200, f"Neg Sc3 ExpGrant Setup Fail Scope: {scope_update.text}"

        # Create expired grant
        expired_grant = self._create_user_jwt_grant(issuer_subject, issuer_subject, exp_offset_seconds=-600)
        # Attempt token request
        token_res = self._get_token_jwt_bearer_grant(client_id, DEFAULT_CLIENT_SECRET, expired_grant, DEFAULT_TEST_SCOPE)
        assert token_res.status_code != 200, f"Neg Sc3 ExpGrant: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc3 ExpGrant: Token request failed due to expired grant as expected ({token_res.status_code})")
    
    @allure.title("Negative test - Grant with wrong signature")
    @allure.description("Confirms that authorization grants signed with incorrect keys are rejected for JWT token issuance")
    def test_neg_s3_grant_wrong_signature(self):
        print("\n\n=== Running Neg Sc3: Grant with Wrong Signature (JWT Token Strategy) ===")
        # Setup
        client_id = self._generate_unique_id("neg-s3-sigcli")
        issuer_subject = self._generate_unique_id("neg-s3-sigusr")
        user_reg = self._register_user_key_grant(issuer_subject, issuer_subject, scope=DEFAULT_TEST_SCOPE) # Registers with primary key
        assert user_reg.status_code in [200, 201], f"Neg Sc3 Sig Setup Fail UserReg: {user_reg.text}"
        client_reg = self._register_client_with_jwt_strategy(client_id, DEFAULT_CLIENT_SECRET)
        assert client_reg.status_code in [200, 201], f"Neg Sc3 Sig Setup Fail ClientReg: {client_reg.text}"
        scope_update = self._configure_client_scope(client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200, f"Neg Sc3 Sig Setup Fail Scope: {scope_update.text}"

        # Create grant signed with the wrong key
        wrong_key_grant = self._create_user_jwt_grant(issuer_subject, issuer_subject, key_to_use=self.different_jwk_key)
        # Attempt token request
        token_res = self._get_token_jwt_bearer_grant(client_id, DEFAULT_CLIENT_SECRET, wrong_key_grant, DEFAULT_TEST_SCOPE)
        assert token_res.status_code != 200, f"Neg Sc3 Sig: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc3 Sig: Token request failed due to wrong grant signature as expected ({token_res.status_code})")

    @allure.title("Negative test - Grant with invalid audience")
    @allure.description("Ensures JWT grants with incorrect audience values are rejected when requesting JWT access tokens")
    def test_neg_s3_grant_invalid_audience(self):
        print("\n\n=== Running Neg Sc3: Grant with Invalid Audience (JWT Token Strategy) ===")
        # Setup
        client_id = self._generate_unique_id("neg-s3-audcli")
        issuer_subject = self._generate_unique_id("neg-s3-audusr")
        user_reg = self._register_user_key_grant(issuer_subject, issuer_subject, scope=DEFAULT_TEST_SCOPE)
        assert user_reg.status_code in [200, 201], f"Neg Sc3 Aud Setup Fail UserReg: {user_reg.text}"
        client_reg = self._register_client_with_jwt_strategy(client_id, DEFAULT_CLIENT_SECRET)
        assert client_reg.status_code in [200, 201], f"Neg Sc3 Aud Setup Fail ClientReg: {client_reg.text}"
        scope_update = self._configure_client_scope(client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200, f"Neg Sc3 Aud Setup Fail Scope: {scope_update.text}"

        # Create grant assertion with the wrong audience (should be TOKEN_URL)
        wrong_aud_grant = self._create_user_jwt_grant(issuer_subject, issuer_subject, audience="https://some.other.service.invalid")
        # Attempt token request
        token_res = self._get_token_jwt_bearer_grant(client_id, DEFAULT_CLIENT_SECRET, wrong_aud_grant, DEFAULT_TEST_SCOPE)
        assert token_res.status_code != 200, f"Neg Sc3 Aud: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc3 Aud: Token request failed due to invalid grant audience as expected ({token_res.status_code})")

    @allure.title("Negative test - Grant issuer mismatch")
    @allure.description("Verifies that grants from issuers not matching registered values are rejected")
    def test_neg_s3_grant_issuer_mismatch(self):
        print("\n\n=== Running Neg Sc3: Grant Issuer Mismatch (JWT Token Strategy) ===")
        # Setup
        client_id = self._generate_unique_id("neg-s3-isscli")
        registered_issuer_subject = self._generate_unique_id("neg-s3-issus") # This one is registered
        wrong_issuer = f"wrong-issuer-{uuid.uuid4().hex[:8]}" # This one is NOT registered

        # Register the grant for the 'registered_issuer_subject'
        user_reg = self._register_user_key_grant(registered_issuer_subject, registered_issuer_subject, scope=DEFAULT_TEST_SCOPE)
        assert user_reg.status_code in [200, 201], f"Neg Sc3 Iss Setup Fail UserReg: {user_reg.text}"
        # Register the client requesting JWT tokens
        client_reg = self._register_client_with_jwt_strategy(client_id, DEFAULT_CLIENT_SECRET)
        assert client_reg.status_code in [200, 201], f"Neg Sc3 Iss Setup Fail ClientReg: {client_reg.text}"
        scope_update = self._configure_client_scope(client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200, f"Neg Sc3 Iss Setup Fail Scope: {scope_update.text}"

        # Create grant assertion using the WRONG issuer but the registered subject's key/details otherwise
        wrong_issuer_grant = self._create_user_jwt_grant(wrong_issuer, registered_issuer_subject) # Iss doesn't match registered grant
        # Attempt token request
        token_res = self._get_token_jwt_bearer_grant(client_id, DEFAULT_CLIENT_SECRET, wrong_issuer_grant, DEFAULT_TEST_SCOPE)
        assert token_res.status_code != 200, f"Neg Sc3 Iss: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc3 Iss: Token request failed due to grant issuer mismatch/unregistered issuer as expected ({token_res.status_code})")

    @allure.title("Negative test - Request with invalid scope")
    @allure.description("Confirms that requests for unauthorized scopes either fail or result in tokens with reduced permissions")
    def test_neg_s3_request_invalid_scope(self):
        print("\n\n=== Running Neg Sc3: Request Invalid Scope (JWT Token Strategy) ===")
        # Setup
        client_id = self._generate_unique_id("neg-s3-scocli")
        issuer_subject = self._generate_unique_id("neg-s3-scousr")
        # Register user grant allowing only DEFAULT_TEST_SCOPE
        user_reg = self._register_user_key_grant(issuer_subject, issuer_subject, scope=DEFAULT_TEST_SCOPE)
        assert user_reg.status_code in [200, 201], f"Neg Sc3 Scope Setup Fail UserReg: {user_reg.text}"
        # Register client requesting JWT tokens
        client_reg = self._register_client_with_jwt_strategy(client_id, DEFAULT_CLIENT_SECRET)
        assert client_reg.status_code in [200, 201], f"Neg Sc3 Scope Setup Fail ClientReg: {client_reg.text}"
        # Configure client allowing only DEFAULT_TEST_SCOPE (redundant with grant but good practice)
        scope_update = self._configure_client_scope(client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200, f"Neg Sc3 Scope Setup Fail Scope: {scope_update.text}"

        # Create a valid grant assertion
        valid_grant = self._create_user_jwt_grant(issuer_subject, issuer_subject)
        # Attempt token request asking for an INVALID scope
        token_res = self._get_token_jwt_bearer_grant(client_id, DEFAULT_CLIENT_SECRET, valid_grant, INVALID_SCOPE)

        # Expected: Fail or succeed with reduced scope (server dependent)
        if token_res.status_code == 200:
            # Check granted scope if request succeeded
            granted_scope = token_res.json().get("scope", "")
            assert INVALID_SCOPE not in granted_scope.split(), f"Neg Sc3 Scope: Invalid scope '{INVALID_SCOPE}' granted unexpectedly: {granted_scope}"
            print(f"Neg Sc3 Scope: Token granted with reduced/empty scope '{granted_scope}' as expected.")
        else:
            # Check for failure
            assert token_res.status_code != 200, f"Neg Sc3 Scope: Expected failure or reduced scope, got {token_res.status_code}. Body: {token_res.text}"
            print(f"Neg Sc3 Scope: Token request failed due to invalid scope request as expected ({token_res.status_code})")

    @allure.title("Negative test - Tampered grant")
    @allure.description("Verifies token request fails when the grant assertion's payload is modified, invalidating its signature")
    def test_neg_s3_tampered_grant(self):
        print("\n\n=== Running Neg Sc3: Tampered Grant Assertion (JWT Token Strategy) ===")
        # Setup
        client_id = self._generate_unique_id("neg-s3-tampcli")
        issuer_subject = self._generate_unique_id("neg-s3-tampusr")
        user_reg = self._register_user_key_grant(issuer_subject, issuer_subject, scope=DEFAULT_TEST_SCOPE)
        assert user_reg.status_code in [200, 201], f"Neg Sc3 Tamp Setup Fail UserReg: {user_reg.text}"
        client_reg = self._register_client_with_jwt_strategy(client_id, DEFAULT_CLIENT_SECRET)
        assert client_reg.status_code in [200, 201], f"Neg Sc3 Tamp Setup Fail ClientReg: {client_reg.text}"
        scope_update = self._configure_client_scope(client_id, DEFAULT_TEST_SCOPE)
        assert scope_update.status_code == 200, f"Neg Sc3 Tamp Setup Fail Scope: {scope_update.text}"

        # Create valid grant, then tamper with it
        valid_grant = self._create_user_jwt_grant(issuer_subject, issuer_subject)
        tampered_grant = self._tamper_with_jwt(valid_grant)
        assert valid_grant != tampered_grant, "Tampering failed for Neg Sc3 Grant"

        # Attempt token request with the tampered grant (invalid signature)
        token_res = self._get_token_jwt_bearer_grant(client_id, DEFAULT_CLIENT_SECRET, tampered_grant, DEFAULT_TEST_SCOPE)
        assert token_res.status_code != 200, f"Neg Sc3 Tamp: Expected failure, got {token_res.status_code}. Body: {token_res.text}"
        print(f"Neg Sc3 Tamp: Token request failed due to tampered grant (invalid signature) as expected ({token_res.status_code})")