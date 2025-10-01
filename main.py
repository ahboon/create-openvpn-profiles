#!/usr/bin/env python3
import os
import subprocess
import re
import base64
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)

EASYRSA_DIR = Path("/etc/openvpn/server/easy-rsa")
CLIENT_COMMON = Path("/etc/openvpn/server/client-common.txt")
OUTPUT_DIR = Path("/tmp")   # where generated profiles are stored

def run(cmd):
    subprocess.run(cmd, check=True)

@app.route("/create", methods=["GET"])
def create_client():
    if os.geteuid() != 0:
        return jsonify({"error": "This API must run as root."}), 403

    client = request.args.get("client")
    if not client:
        return jsonify({"error": "Missing 'client' parameter"}), 400

    client = re.sub(r'[^0-9A-Za-z_-]', '_', client)

    if not EASYRSA_DIR.exists():
        return jsonify({"error": "Easy-RSA directory not found"}), 500

    try:
        # build client cert
        os.chdir(EASYRSA_DIR)
        run(["./easyrsa", "--batch", "--days=3650", "build-client-full", client, "nopass"])

        inline_file = EASYRSA_DIR / f"pki/inline/private/{client}.inline"
        if not inline_file.exists():
            return jsonify({"error": f"Inline file not found for client {client}"}), 500

        output_file = OUTPUT_DIR / f"{client}.ovpn"

        with open(output_file, "w") as out:
            subprocess.run(
                ["grep", "-vh", "^#", str(CLIENT_COMMON), str(inline_file)],
                stdout=out,
                check=True
            )

        with open(output_file, "rb") as f:
            encoded = base64.b64encode(f.read()).decode("utf-8")

        return jsonify({"client": client, "ovpn_base64": encoded})

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Command failed: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/delete", methods=["POST"])
def delete_client():
    if os.geteuid() != 0:
        return jsonify({"error": "This API must run as root."}), 403

    data = request.get_json(force=True)
    client = data.get("client") if data else None

    if not client:
        return jsonify({"error": "Missing 'client' field in JSON body"}), 400

    client = re.sub(r'[^0-9A-Za-z_-]', '_', client)

    if not EASYRSA_DIR.exists():
        return jsonify({"error": "Easy-RSA directory not found"}), 500

    try:
        os.chdir(EASYRSA_DIR)

        # revoke the certificate
        run(["bash", "-c", "echo yes | ./easyrsa revoke {}".format(client)])

        # regenerate CRL
        run(["./easyrsa", "gen-crl"])

        # remove generated profile if exists
        ovpn_file = OUTPUT_DIR / f"{client}.ovpn"
        if ovpn_file.exists():
            ovpn_file.unlink()

        return jsonify({"message": f"Client '{client}' revoked and removed."})

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Command failed: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
