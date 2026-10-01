"""Stdlib-only TLS 1.3 capture-node stand-in run as a separate test process.

Arguments are file paths and a synthetic server name only; key material never
appears in argv or the environment. Prints one fixed result word.
"""
import socket
import ssl
import sys


def main(argv):
    port, ca_path, server_name, certificate, key, payload = argv
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=ca_path)
    if certificate != "-":
        context.load_cert_chain(certfile=certificate, keyfile=key)
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=10) as raw:
            if payload == "plaintext":
                raw.sendall(b"GET / HTTP/1.1\r\nHost: capture\r\n\r\n")
                try:
                    reply = raw.recv(64)
                except OSError:
                    reply = b""
                print("http-response" if reply.startswith(b"HTTP/") else "no-http-response")
                return 0
            with context.wrap_socket(raw, server_hostname=server_name) as tls:
                tls.sendall(b"ping")
                print("ok" if tls.recv(4) == b"pong" else "closed")
                return 0
    except ssl.SSLCertVerificationError:
        print("server-rejected")
        return 3
    except (ssl.SSLError, OSError):
        print("refused")
        return 4


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
