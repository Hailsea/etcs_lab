import socket
import json
import hmac
import hashlib
import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = "0.0.0.0"
PORT = 5000
SESSION_KEY_LIFETIME = 1800  # 30 minutes

sessions = {}

# ============================================================
# GENERATION PAIRE DE CLES RSA (KMC simule)
# ============================================================

print("[RBC] Génération de la paire de clés RSA...")
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()
print("[RBC] Paire de clés RSA générée")

# ============================================================
# SIMULATION AXLE COUNTERS + LEU
# ============================================================

TRACK_SECTIONS = [
    {"id": 1, "start": 0,    "end": 500,  "state": "free"},
    {"id": 2, "start": 500,  "end": 1000, "state": "free"},
    {"id": 3, "start": 1000, "end": 1500, "state": "free"},
    {"id": 4, "start": 1500, "end": 2000, "state": "occupied"},
    {"id": 5, "start": 2000, "end": 2500, "state": "free"},
    {"id": 6, "start": 2500, "end": 3000, "state": "free"},
]

LEU_SIGNAL = {"position": 1500, "state": "closed"}

def get_eoa(train_position):
    eoa_axle = 99999
    eoa_leu = 99999
    for section in TRACK_SECTIONS:
        if section["start"] >= train_position and section["state"] == "occupied":
            eoa_axle = section["start"]
            break
    if LEU_SIGNAL["position"] > train_position and LEU_SIGNAL["state"] == "closed":
        eoa_leu = LEU_SIGNAL["position"]
    eoa = min(eoa_axle, eoa_leu)
    print(f"[RBC] EOA calculée — Axle: {eoa_axle}m | LEU: {eoa_leu}m | EOA finale: {eoa}m")
    return eoa

# ============================================================
# HMAC
# ============================================================

def generate_session_key():
    return os.urandom(32)

def compute_hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()

def verify_hmac(key, msg, received_mac):
    expected = compute_hmac(key, msg)
    return hmac.compare_digest(expected, received_mac)

def decrypt_session_key(encrypted_key_hex):
    encrypted_bytes = bytes.fromhex(encrypted_key_hex)
    session_key = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return session_key

# ============================================================
# TRAITEMENT DES MESSAGES
# ============================================================

def handle_message(sock, data, addr):
    msg = json.loads(data.decode())
    msg_type = msg.get("type")

    # Message 155 : Initiation of communication session
    # Le RBC envoie sa cle publique RSA — l EVC va chiffrer la cle de session avec
    if msg_type == "155":
        train_id = msg["train_id"]
        sessions[train_id] = {
            "key": None,
            "created_at": None,
            "addr": addr,
            "t_cycloc": 6
        }
        print(f"[RBC] MSG 155 reçu — Train {train_id}")
        # Returns a Message 32 : RSA public key 
        rep = {"type": "32", "rbc_id": "RBC_01", "version": "3.6.0",
               "public_key": public_key_pem}
        sock.sendto(json.dumps(rep).encode(), addr)
        print(f"[RBC] MSG 32 envoyé — clé publique RSA transmise")

    # Message 159 : Session Established + cle de session chiffree par l EVC
    elif msg_type == "159":
        train_id = msg["train_id"]
        session = sessions.get(train_id)
        if not session:
            return
        encrypted_key = msg.get("encrypted_session_key")
        session_key = decrypt_session_key(encrypted_key)
        session["key"] = session_key
        session["created_at"] = time.time()
        print(f"[RBC] MSG 159 reçu — Clé de session déchiffrée avec RSA ✅")

    elif msg_type == "129":
        train_id = msg["train_id"]
        session = sessions.get(train_id)
        if not session or not session["key"]:
            return
        ack = {"type": "8", "train_id": train_id}
        sock.sendto(json.dumps(ack).encode(), addr)
        print(f"[RBC] MSG 8 envoyé — ACK Train Data")
        t_cycloc = session["t_cycloc"]

        # Returns a Message 24 : with train_id and t_cycloc
        gm = {"type": "24", "train_id": train_id, "t_cycloc": t_cycloc}
        payload = json.dumps(gm, separators=(',', ':'))
        gm["hmac"] = compute_hmac(session["key"], payload)
        sock.sendto(json.dumps(gm).encode(), addr)
        print(f"[RBC] MSG 24 envoyé — T_CYCLOC={t_cycloc}s")

    elif msg_type == "146":
        train_id = msg["train_id"]
        print(f"[RBC] MSG 146 reçu — ACK General Message par {train_id}")

    elif msg_type == "132":
        train_id = msg["train_id"]
        session = sessions.get(train_id)
        if not session or not session["key"]:
            return
        print(f"[RBC] MSG 132 reçu — MA Request de {train_id}")
        eoa = get_eoa(0)
        ma = {"type": "3", "train_id": train_id, "eoa": eoa, "v_max": 160}
        payload = json.dumps(ma, separators=(',', ':'))
        ma["hmac"] = compute_hmac(session["key"], payload)
        sock.sendto(json.dumps(ma).encode(), addr)
        print(f"[RBC] MA initiale envoyée — EOA: {eoa}m")

    elif msg_type == "136":
        train_id = msg["train_id"]
        session = sessions.get(train_id)
        if not session or not session["key"]:
            return
        if time.time() - session["created_at"] > SESSION_KEY_LIFETIME:
            print(f"[RBC] Clé expirée pour {train_id} — renouvellement")
            new_key = generate_session_key()
            session["key"] = new_key
            session["created_at"] = time.time()
            renewal = {"type": "KEY_RENEWAL", "train_id": train_id,
                       "session_key": new_key.hex()}
            sock.sendto(json.dumps(renewal).encode(), addr)
        received_mac = msg.pop("hmac", "")
        payload = json.dumps(msg, separators=(',', ':'))
        if not verify_hmac(session["key"], payload, received_mac):
            print(f"[RBC] HMAC invalide — TPR rejeté")
            return
        position = msg["position"]
        speed = msg["speed"]
        print(f"[RBC] TPR reçu — Train: {train_id} | Position: {position}m | Vitesse: {speed}km/h")
        eoa = get_eoa(position)
        ma = {"type": "3", "train_id": train_id, "eoa": eoa, "v_max": 160}
        payload = json.dumps(ma, separators=(',', ':'))
        ma["hmac"] = compute_hmac(session["key"], payload)
        sock.sendto(json.dumps(ma).encode(), addr)
        print(f"[RBC] MA envoyée — EOA: {eoa}m")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))
print(f"[RBC] En écoute sur {HOST}:{PORT}")
print(f"[RBC] LEU signal à {LEU_SIGNAL['position']}m — état: {LEU_SIGNAL['state']}")
for s in TRACK_SECTIONS:
    print(f"[RBC] Section {s['id']}: {s['start']}m-{s['end']}m — {s['state']}")

while True:
    data, addr = sock.recvfrom(4096)
    try:
        handle_message(sock, data, addr)
    except Exception as e:
        print(f"[RBC] Erreur: {e}")
