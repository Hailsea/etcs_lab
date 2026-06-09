import socket
import json
import hmac
import hashlib
import time
import os
import threading
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

RBC_HOST = "192.168.70.129"
RBC_PORT = 5000
BIND_IP = "12.1.1.130"
BIND_PORT = 5001
ATTACK_PORT = 5002
TRAIN_ID = "TRAIN_001"

BALISES = {500: 500, 1500: 1500}

session_key = None
t_cycloc = 6
position = 0
speed = 100
eoa = 99999

def compute_hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()

def verify_hmac(key, msg, received_mac):
    expected = compute_hmac(key, msg)
    return hmac.compare_digest(expected, received_mac)

def encrypt_session_key(session_key_bytes, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted = public_key.encrypt(
        session_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted.hex()

# ============================================================
# THREAD ATTAQUES — ecoute en permanence sur port 5002
# ============================================================

def listen_attacks():
    global position, speed, eoa, session_key
    attack_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    attack_sock.bind((BIND_IP, ATTACK_PORT))
    print(f"[EVC] Thread attaques actif — écoute sur {BIND_IP}:{ATTACK_PORT}")
    while True:
        try:
            data, _ = attack_sock.recvfrom(4096)
            msg = json.loads(data.decode())

            # ATTAQUE 3 — message haute priorite
            if msg.get("type") == "3" and msg.get("priority") == "high":
                eoa = msg["eoa"]
                speed = msg.get("v_max", 0)
                print(f"[EVC] ⚠️ FAILLE — Message haute priorité accepté sans vérification HMAC !")
                print(f"[EVC] ⚠️ EOA forcée à {eoa}m | Vitesse forcée à {speed}km/h")

            # ATTAQUE 4 — fausse balise
            elif msg.get("type") == "BALISE":
                fake_pos = msg["position"]
                print(f"[EVC] ⚠️ FAILLE — Fausse balise reçue — recalage position à {fake_pos}m")
                print(f"[EVC] ⚠️ Position était {position}m — maintenant recalée à {fake_pos}m")
                position = fake_pos

        except Exception as e:
            pass

# ============================================================
# SOCKET PRINCIPAL
# ============================================================

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((BIND_IP, BIND_PORT))
sock.settimeout(5.0)
print(f"[EVC] Démarrage — bindé sur {BIND_IP}:{BIND_PORT}")

# ============================================================
# PHASE 1 : Handshake EuroRadio avec RSA
# ============================================================

msg155 = {"type": "155", "train_id": TRAIN_ID, "t_train": int(time.time())}
sock.sendto(json.dumps(msg155).encode(), (RBC_HOST, RBC_PORT))
print("[EVC] MSG 155 envoyé — Initiation session")

data, _ = sock.recvfrom(4096)
msg32 = json.loads(data.decode())
assert msg32["type"] == "32", "Attendu MSG 32"
public_key_pem = msg32["public_key"]
print(f"[EVC] MSG 32 reçu — Clé publique RSA du RBC reçue")

session_key = os.urandom(32)
encrypted_session_key = encrypt_session_key(session_key, public_key_pem)
print(f"[EVC] Clé de session générée et chiffrée avec RSA")

msg159 = {"type": "159", "train_id": TRAIN_ID,
          "encrypted_session_key": encrypted_session_key}
sock.sendto(json.dumps(msg159).encode(), (RBC_HOST, RBC_PORT))
print("[EVC] MSG 159 envoyé — Clé de session chiffrée transmise au RBC")

msg129 = {"type": "129", "train_id": TRAIN_ID, "v_maxtrain": 160, "train_length": 200}
sock.sendto(json.dumps(msg129).encode(), (RBC_HOST, RBC_PORT))
print("[EVC] MSG 129 envoyé — Train Data")

data, _ = sock.recvfrom(4096)
msg8 = json.loads(data.decode())
assert msg8["type"] == "8", "Attendu MSG 8"
print("[EVC] MSG 8 reçu — ACK Train Data")

data, _ = sock.recvfrom(4096)
msg24 = json.loads(data.decode())
assert msg24["type"] == "24", "Attendu MSG 24"
received_mac = msg24.pop("hmac", "")
payload = json.dumps(msg24, separators=(',', ':'))
assert verify_hmac(session_key, payload, received_mac), "HMAC MSG 24 invalide"
t_cycloc = msg24["t_cycloc"]
print(f"[EVC] MSG 24 reçu — T_CYCLOC={t_cycloc}s")

msg146 = {"type": "146", "train_id": TRAIN_ID, "t_train_ack": int(time.time())}
sock.sendto(json.dumps(msg146).encode(), (RBC_HOST, RBC_PORT))
print("[EVC] MSG 146 envoyé — ACK General Message")

msg132 = {"type": "132", "train_id": TRAIN_ID}
sock.sendto(json.dumps(msg132).encode(), (RBC_HOST, RBC_PORT))
print("[EVC] MSG 132 envoyé — MA Request")

data, _ = sock.recvfrom(4096)
ma_init = json.loads(data.decode())
assert ma_init["type"] == "3", "Attendu MSG 3"
received_mac = ma_init.pop("hmac", "")
payload = json.dumps(ma_init, separators=(',', ':'))
assert verify_hmac(session_key, payload, received_mac), "HMAC MA initiale invalide"
eoa = ma_init["eoa"]
print(f"[EVC] MA initiale reçue — EOA: {eoa}m")

print("[EVC] ✅ Handshake terminé avec chiffrement RSA — début communication normale")

# Lancement thread attaques
attack_thread = threading.Thread(target=listen_attacks, daemon=True)
attack_thread.start()

# ============================================================
# PHASE 2 : Communication normale TPR / MA
# ============================================================

while True:
    position += int(speed * t_cycloc / 3.6)

    # Recalage balise interne
    for balise_pos, balise_val in BALISES.items():
        if abs(position - balise_pos) < 100:
            print(f"[EVC] Balise détectée à {balise_pos}m — recalage position")
            position = balise_val

    # Verification EOA
    if position >= eoa:
        print(f"[EVC] ⚠️ EOA atteint ({eoa}m) — arrêt d'urgence !")
        speed = 0

    # Envoi TPR (Message 136)
    tpr = {"type": "136", "train_id": TRAIN_ID, "position": position,
           "speed": speed, "direction": 1, "t_train": int(time.time())}
    payload = json.dumps(tpr, separators=(',', ':'))
    tpr["hmac"] = compute_hmac(session_key, payload)
    sock.sendto(json.dumps(tpr).encode(), (RBC_HOST, RBC_PORT))
    print(f"[EVC] TPR envoyé — Position: {position}m | Vitesse: {speed}km/h")

    # Reception MA (Message 3)
    try:
        data, _ = sock.recvfrom(4096)
        msg = json.loads(data.decode())

        # Renouvellement cle
        if msg.get("type") == "KEY_RENEWAL":
            session_key = bytes.fromhex(msg["session_key"])
            print("[EVC] 🔑 Clé de session renouvelée")
            data, _ = sock.recvfrom(4096)
            msg = json.loads(data.decode())

        # MA normale
        if msg.get("type") == "3":
            received_mac = msg.pop("hmac", "")
            payload = json.dumps(msg, separators=(',', ':'))
            if verify_hmac(session_key, payload, received_mac):
                eoa = msg["eoa"]
                print(f"[EVC] MA reçue — EOA: {eoa}m | V_max: {msg['v_max']}km/h")
            else:
                print("[EVC] ⚠️ MA rejetée — HMAC invalide ! (tentative de spoofing détectée)")

    except socket.timeout:
        print("[EVC] Pas de message reçu (timeout)")

    time.sleep(t_cycloc)
