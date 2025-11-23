#!/usr/bin/env python3
"""
Script: mon-ECC/monECC
Création: Mathias SOLER, le 28/10/2025
"""

# Imports :
import argparse
import sys
from random import randint
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Paramètres de la courbe :
# y^2 = x^3 + 35x + 3 (modulo 101)
a = 35
b = 3
m = 101
p = (2, 9)

# Fonctions :
def recadrage(p):
    """
    Calcul modulo p de P
    on  veut que les coordonées de P soient entre -p/2 et (p/2)-1
    """
    px, py = p
    lim_basse = (int)(m / 2) * -1
    lim_haute = (int)(m / 2) - 1

    if px < lim_basse:
        px = px + m
    if py < lim_basse:
        py = px + m
    if px > lim_haute:
        px = px - m
    if py > lim_haute:
        py = py - m

    return px, py


def point_add(p1, p2):
    """
    Addition de deux points x1 et Q sur la courbe elliptique
    """
    # Point à l'infini (élément neutre)
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2:
        return None

    # Calcul de la pente
    if p1 == p2:
        # Cas particulier : y1 == 0 mod m → pas d’inverse → point à l’infini
        if (2 * y1) % m == 0:
            return None

        pente = (3 * x1 ** 2 + a) * pow(2 * y1, -1, m)
    else:
        pente = ((y2 - y1) * pow(x2 - x1, -1, m))
    pente %= m

    # Calcul du nouveau point
    x3 = (pente * pente - x1 - x2) % m
    y3 = (pente * (x1 - x3) - y1) % m
    return recadrage([x3, y3])


def point_mult(k, point):
    q = None
    p_inter = point
    while k:
        if k & 1:
            q = point_add(q, p_inter)
        p_inter = point_add(p_inter, p_inter)
        k >>= 1
    return q


def keygen():
    k = randint(1, 1001)
    q = point_mult(k, p)

    with open("monECC.priv", "w") as f:
        f.write("---begin monECC private key---\n")
        f.write(base64.b64encode(str(k).encode()).decode() + "\n")
        f.write("---end monECC key---")

    with open("monECC.pub", "w") as f:
        f.write("---begin monECC public key---\n")
        pub_data = f"{q[0]};{q[1]}"
        f.write(base64.b64encode(pub_data.encode()).decode() + "\n")
        f.write("---end monECC key---")

def crypt(pub, text):
    with open(pub, "r") as f:
        pub_key = f.readlines()

    if pub_key[0] == "---begin monECC public key---":
        qx, qy = base64.b64decode(pub_key[1]).split(";")
        return qx, qy
        with open("monECC.priv", "r") as f:
            priv_key = f.readlines()[1]
        sx, sy = point_mult(base64.b64decode(priv_key), pub_key)

        secret_partage = hashlib.sha256(sx)
        secret_partage = hashlib.sha256(sy)

        iv = secret_partage[:16]  # 16 premiers chars dans IV
        cle = secret_partage[-16:]  # Le reste comme clé
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(text.encode('utf-8'))
        padded_data += padder.finalize()
        cipher = Cipher(algorithms.AES(cle), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return f"Le texte chiffré est {ciphertext}"

    else:
        return "La clé n'est pas du bon format"

def decrypt(priv, text):
    with open(priv, "r") as f:
        priv_key = f.readlines()

    if priv_key[0] == "---begin monECC private key---":
        qx, qy = base64.b64decode(priv_key[1]).split(";")
        return qx, qy
        with open("monECC.pub", "r") as f:
            pub_key = f.readlines()
        sx, sy = point_mult(base64.b64decode(pub_key), priv_key)

        secret_partage = hashlib.sha256(sx)
        secret_partage = hashlib.sha256(sy)

        iv = secret_partage[:16]  # 16 premiers chars dans IV
        cle = secret_partage[-16:]  # Le reste comme clé
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(text.encode('utf-8'))
        padded_data += padder.finalize()
        cipher = Cipher(algorithms.AES(cle), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return f"Le texte déchiffré est {ciphertext}"

    else:
        return "La clé n'est pas du bon format"


def help():
    print("""
    Script monECC par Mathias SOLER
    Syntaxe :
    monECC <commande> [<clé>] [<texte>] [switchs]
    Commandes :
        keygen                  Génère une paire de clés
        crypt <pub> <txt>       Chiffre un texte pour la clé publique
        decrypt <priv> <txt>    Déchiffre un texte pour la clé privée
        help                    Affiche ce manuel
        """
    )


# Programme principal :
def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("commande", nargs="?", default="help")
    parser.add_argument("cle", nargs="?")
    parser.add_argument("texte", nargs="?")

    args = parser.parse_args()

    if args.commande == "help":
        help()
    elif args.commande == "keygen":
        keygen()
    elif args.commande == "crypt":
        if not args.cle or not args.texte:
            print("Mauvaise utilisation, la bonne est : monECC crypt <clé.pub> <texte>")
        else:
            crypt(args.cle, args.texte)
    elif args.commande == "decrypt":
        if not args.cle or not args.texte:
            sys.exit("Bonne utilisation : monECC decrypt <clé.priv> <texte>")
        else:
         decrypt(args.cle, args.texte)
    else:
        print("Commande invalide")
        help()


if __name__ == '__main__':
    main()

