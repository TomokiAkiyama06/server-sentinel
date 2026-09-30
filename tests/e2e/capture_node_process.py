"""Separate ``media-capture-agent`` process for the capture mTLS E2E scenario.

Only file paths, a port and fixed words cross argv; the node private key is
generated, stored and used inside this process's private runtime directory.
Prints one fixed result word.
"""
import sys
from pathlib import Path

from media_capture_agent.node_tls import (
    PendingNodeKeyStore, TrustBundle, build_capture_client_context, build_enrollment_request,
    connect_to_main, installed_credential, validate_issued_credential,
)
from media_capture_agent.pairing import NodeCredentialStore, PairingRefused


def main(argv):
    action, runtime = argv[0], Path(argv[1])
    try:
        if action == "request":
            request = build_enrollment_request(PendingNodeKeyStore(runtime).create())
            Path(argv[2]).write_bytes(request.csr_pem)
            Path(argv[3]).write_text(request.public_key_digest)
        elif action == "install":
            bundle = TrustBundle.parse(Path(argv[2]).read_bytes(), expected_sha256=argv[4])
            pending = PendingNodeKeyStore(runtime)
            material = validate_issued_credential(bundle, pending.load(), Path(argv[3]).read_bytes())
            NodeCredentialStore(runtime).install(material)
            pending.discard()
        elif action == "connect":
            credential = installed_credential(NodeCredentialStore(runtime))
            context = build_capture_client_context(credential.ca_certificate_pem,
                                                   certificate_path=credential.certificate_path,
                                                   key_path=credential.key_path)
            with connect_to_main(context, server_name=credential.server_name,
                                 host="127.0.0.1", port=int(argv[2])) as connection:
                connection.sendall(b"ping")
                reply = connection.recv(4)
                print("ok" if reply == b"pong" else "closed")
                return 0
        else:
            return 2
    except PairingRefused as error:
        print(str(error))
        return 3
    except OSError:
        print("closed")
        return 4
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
