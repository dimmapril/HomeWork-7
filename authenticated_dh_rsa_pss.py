#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Authenticated Diffie–Hellman with RSA-PSS (both sides in one script).
- Library: cryptography (hazmat)
- Model: each side has a long-term RSA signing key; they authenticate their ephemeral DH keys by signing them.
- Transport is mocked by local variables; focus is on the cryptographic flow.

Author: (your name)
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple, Optional
from os import path
import sys
from binascii import hexlify

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, PublicFormat,
    load_pem_private_key, load_pem_public_key,
)
from cryptography.exceptions import InvalidSignature

# ---------- Helpers for RSA key management ----------

def load_or_create_rsa_keypair(priv_path: str, pub_path: str, bits: int = 3072):
    """
    Load RSA private/public PEM if present, otherwise create and save them.
    Returns (private_key, public_key).
    """
    if path.exists(priv_path):
        with open(priv_path, 'rb') as f:
            private_key = load_pem_private_key(f.read(), password=None)
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        with open(priv_path, 'wb') as f:
            f.write(private_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            ))

    public_key = private_key.public_key()
    if not path.exists(pub_path):
        with open(pub_path, 'wb') as f:
            f.write(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    return private_key, public_key

# ---------- Messages ----------

@dataclass
class SignedDHPublic:
    """
    What each side sends in an authenticated DH:
    - dh_pub_pem: the ephemeral DH public key (PEM-encoded SubjectPublicKeyInfo)
    - signature: RSA-PSS signature over a transcript-bound message
    - signer_id: who signed it (for logging/demo)
    """
    dh_pub_pem: bytes
    signature: bytes
    signer_id: str

# ---------- Core logic per side ----------

class Party:
    def __init__(self, name: str, rsa_priv_path: str, rsa_pub_path: str):
        self.name = name
        self.rsa_private, self.rsa_public = load_or_create_rsa_keypair(rsa_priv_path, rsa_pub_path)

        # Will be set during the protocol
        self.parameters: Optional[dh.DHParameters] = None
        self.dh_private: Optional[dh.DHPrivateKey] = None
        self.dh_public_pem: Optional[bytes] = None

    # ---- DH parameter setup ----
    def setup_parameters(self, parameters: Optional[dh.DHParameters] = None):
        if parameters is None:
            # Safe defaults: generator=2, 2048-bit modp
            self.parameters = dh.generate_parameters(generator=2, key_size=2048)
        else:
            self.parameters = parameters

    # ---- Ephemeral DH keypair ----
    def gen_ephemeral(self):
        assert self.parameters is not None, "DH parameters must be set first"
        self.dh_private = self.parameters.generate_private_key()
        dh_public = self.dh_private.public_key()
        self.dh_public_pem = dh_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    # ---- Sign the DH public with RSA-PSS ----
    def sign_dh_public(self, peer_name: str) -> SignedDHPublic:
        """
        We bind the signature to a context "DH1" + identities + DH parameters hash + public key bytes.
        This thwarts substitution and some reflection attacks.
        """
        assert self.dh_public_pem is not None and self.parameters is not None

        # Hash DH parameters (p,g) + our public
        h = hashes.Hash(hashes.SHA256())
        # Serialize p and g deterministically
        numbers = self.parameters.parameter_numbers()
        p_bytes = numbers.p.to_bytes((numbers.p.bit_length() + 7) // 8, 'big')
        g_bytes = numbers.g.to_bytes((numbers.g.bit_length() + 7) // 8, 'big')
        h.update(b"CTX:DH1|")
        h.update(self.name.encode('utf-8') + b"->" + peer_name.encode('utf-8') + b"|")
        h.update(b"p=" + p_bytes + b"|g=" + g_bytes + b"|")
        h.update(b"pub=" + self.dh_public_pem)
        digest = h.finalize()

        signature = self.rsa_private.sign(
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return SignedDHPublic(dh_pub_pem=self.dh_public_pem, signature=signature, signer_id=self.name)

    # ---- Verify peer's signed DH public ----
    def verify_peer_message(self, msg: SignedDHPublic, peer_pubkey) -> dh.DHPublicKey:
        assert self.parameters is not None

        # Recompute the same transcript hash from *our* perspective (peer -> self)
        numbers = self.parameters.parameter_numbers()
        p_bytes = numbers.p.to_bytes((numbers.p.bit_length() + 7) // 8, 'big')
        g_bytes = numbers.g.to_bytes((numbers.g.bit_length() + 7) // 8, 'big')

        h = hashes.Hash(hashes.SHA256())
        h.update(b"CTX:DH1|")
        h.update(msg.signer_id.encode('utf-8') + b"->" + self.name.encode('utf-8') + b"|")
        h.update(b"p=" + p_bytes + b"|g=" + g_bytes + b"|")
        h.update(b"pub=" + msg.dh_pub_pem)
        digest = h.finalize()

        try:
            peer_pubkey.verify(
                msg.signature,
                digest,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        except InvalidSignature as e:
            raise RuntimeError(f"[{self.name}] Signature verification FAILED for {msg.signer_id}") from e

        # Load peer's DH public key from PEM
        peer_dh_public = serialization.load_pem_public_key(msg.dh_pub_pem)
        assert isinstance(peer_dh_public, dh.DHPublicKey), "Loaded key is not a DHPublicKey"
        return peer_dh_public

    # ---- Compute shared secret and derive keys ----
    def derive_session_key(self, peer_dh_public: dh.DHPublicKey, transcript_info: bytes) -> bytes:
        assert self.dh_private is not None
        shared_secret = self.dh_private.exchange(peer_dh_public)
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,            # For demo; consider a salt = transcript hash in production.
            info=transcript_info, # Binds context to the derived key.
        ).derive(shared_secret)
        return key

# ---------- Demo of the full flow ----------

def main():
    # Long-term RSA keys (will be created next to the script if missing)
    alice = Party("Alice", "alice_rsa_priv.pem", "alice_rsa_pub.pem")
    bob   = Party("Bob",   "bob_rsa_priv.pem",   "bob_rsa_pub.pem")

    # Each side "knows" the other's public key beforehand (PKI/certificates in real life)
    alice_view_of_bob_pub = bob.rsa_public
    bob_view_of_alice_pub = alice.rsa_public

    # --- 1) Agree on DH parameters (here: generated by Alice and shared) ---
    alice.setup_parameters()                           # Alice chooses safe parameters
    bob.setup_parameters(alice.parameters)             # Bob accepts

    # --- 2) Generate ephemeral DH keys ---
    alice.gen_ephemeral()
    bob.gen_ephemeral()

    # --- 3) Sign own ephemeral DH public keys with RSA-PSS ---
    to_bob   = alice.sign_dh_public(peer_name="Bob")
    to_alice = bob.sign_dh_public(peer_name="Alice")

    # --- 4) Verify signatures and parse peer DH public keys ---
    bob_peer_dh_pub   = bob.verify_peer_message(to_bob,   peer_pubkey=bob_view_of_alice_pub)
    alice_peer_dh_pub = alice.verify_peer_message(to_alice, peer_pubkey=alice_view_of_bob_pub)

    # --- 5) Derive the same session key ---
    numbers = alice.parameters.parameter_numbers()
    p_bytes = numbers.p.to_bytes((numbers.p.bit_length() + 7) // 8, 'big')
    g_bytes = numbers.g.to_bytes((numbers.g.bit_length() + 7) // 8, 'big')
    transcript_info = b"CTX:DH1|" + b"p=" + p_bytes + b"|g=" + g_bytes + b"|Alice|Bob"

    alice_key = alice.derive_session_key(alice_peer_dh_pub, transcript_info)
    bob_key   = bob.derive_session_key(bob_peer_dh_pub,     transcript_info)

    # --- 6) Output ---
    print("DH modulus bits:", numbers.p.bit_length())
    print("Alice session key:", hexlify(alice_key).decode())
    print("Bob   session key:", hexlify(bob_key).decode())
    print("Keys equal? ->", alice_key == bob_key)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        sys.exit(1)
