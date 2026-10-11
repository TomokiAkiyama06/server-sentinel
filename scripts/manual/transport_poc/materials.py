"""Disposable, test-only PKI and pairing ledger for the transport PoC.

Everything is created with the product code (``node_ca.DeploymentAuthority``,
``pairing.PairingLedger``) in one owner-only (0700) directory OUTSIDE the
repository. It is never the deployment's real CA or ledger: delete the whole
directory after the PoC (README cleanup checklist).

Layout (``ROOT``)::

    deployment.json         deployment id, server name, node ids by label
    authority/              disposable deployment CA (private key)
    listener/               Main ingest listener certificate and key
    other-authority/        a second, unrelated CA (negative test only)
    ledger.sqlite3          disposable pairing ledger + audit tables
    nodes/<label>/          ca.pem, cert.pem, key.pem (0600), node.json

Node labels: ``good`` (paired, active), ``revoked_live`` (paired; revoked by
the ``auth_revoked_live`` scenario while connected), ``revoked`` (paired then
revoked), ``unpaired`` (certificate from the deployment CA, never activated)
and ``other_ca`` (certificate from the unrelated CA).
"""
import datetime
import json
import os
from pathlib import Path
from uuid import UUID, uuid4

SERVER_NAME = "capture-main.poc15.test"
LABELS = ("good", "revoked_live", "revoked", "unpaired", "other_ca")
DAY = datetime.timedelta(days=1)
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class MaterialsError(RuntimeError):
    pass


class _Owner:
    """Stand-in Owner authorizer for the disposable ledger only."""

    def require_owner(self, actor_context):
        if actor_context != "poc15-owner":
            raise PermissionError("synthetic denial")


def require_outside_repository(path):
    path = Path(path).resolve()
    if path == REPOSITORY_ROOT or REPOSITORY_ROOT in path.parents:
        raise MaterialsError("materials and outputs must be outside the repository")
    return path


def private_directory(path, *, exist_ok=False):
    path = require_outside_repository(path)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        if not exist_ok:
            raise MaterialsError("directory already exists") from None
    info = os.lstat(path)
    if info.st_uid != os.geteuid() or info.st_mode & 0o077 or not os.path.isdir(path):
        raise MaterialsError("directory must be a private (0700) directory of this user")
    return path


def _write_private(path, data, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def _ledger(root):
    root = Path(root).resolve()
    from contextlib import closing
    from app.audit.store import AuditStore
    from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingLedger
    from app.storage.database import Database
    from app.storage.migrations import migrate
    from app.storage.schema import APPLICATION_MIGRATIONS
    database = Database(Path(root) / "ledger.sqlite3")
    with closing(database.connect()) as connection:
        migrate(connection, APPLICATION_MIGRATIONS)
    return PairingLedger(database, HmacCodeVerifier(os.urandom(32)), audit=AuditStore(database))


def open_ledger(root):
    return _ledger(root)


def load_deployment(root):
    with open(Path(root) / "deployment.json", encoding="ascii") as stream:
        value = json.load(stream)
    return {"deployment_id": UUID(value["deployment_id"]), "server_name": value["server_name"],
            "nodes": {label: UUID(node) for label, node in value["nodes"].items()}}


def _save_deployment(root, deployment):
    path = Path(root) / "deployment.json"
    data = json.dumps({"deployment_id": str(deployment["deployment_id"]),
                       "server_name": deployment["server_name"],
                       "nodes": {k: str(v) for k, v in deployment["nodes"].items()}},
                      sort_keys=True).encode("ascii")
    temporary = path.with_suffix(".tmp")
    _write_private(temporary, data)
    os.replace(temporary, path)


def _authority(root, name):
    root = Path(root).resolve()
    from app.cameras.remote_agent.node_ca import DeploymentAuthority, PrivateDirectory
    deployment = load_deployment(root)
    deployment_id = deployment["deployment_id"] if name == "authority" else _other_id(root)
    return DeploymentAuthority.load(PrivateDirectory(Path(root) / name), deployment_id)


def _other_id(root):
    with open(Path(root) / "other-authority.json", encoding="ascii") as stream:
        return UUID(json.load(stream)["deployment_id"])


def _new_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    return key, pem


def _csr(key):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    return (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))


def _node_bundle(root, label, node_id, certificate_pem, key_pem, ca_pem):
    directory = private_directory(Path(root) / "nodes" / label)
    _write_private(directory / "ca.pem", ca_pem, 0o644)
    _write_private(directory / "cert.pem", certificate_pem, 0o644)
    if key_pem is not None:
        _write_private(directory / "key.pem", key_pem)
    _write_private(directory / "node.json", json.dumps(
        {"node_id": str(node_id), "server_name": SERVER_NAME}).encode("ascii"), 0o644)
    return directory


def _pair(ledger, authority, csr_pem, key_digest, *, activate=True):
    approval, code = ledger.approve(_Owner(), "poc15-owner", node_id=uuid4(),
                                    public_key_digest=key_digest)
    claim = ledger.redeem(enrollment_id=approval.enrollment_id,
                          public_key_digest=key_digest, code=code.value)
    if activate:
        return authority.issue_and_activate(ledger, claim, csr_pem, validity=7 * DAY)
    return authority.issue_node_certificate(claim, csr_pem, validity=7 * DAY)


NEGATIVE_LABELS = ("revoked", "unpaired", "other_ca")


def init(root, *, with_nodes=True, negatives_only=False):
    """Create the disposable CA, listener credential, ledger and node bundles.

    ``negatives_only`` (real two-host runs) creates only the negative-test
    bundles; the positive ``good``/``revoked_live`` keys are generated on the
    capture host (``node_key``) and issued from their CSR (``issue``).
    """
    from app.cameras.remote_agent.node_ca import (DeploymentAuthority, PrivateDirectory,
                                                  public_key_digest)
    root = private_directory(root)
    deployment = {"deployment_id": uuid4(), "server_name": SERVER_NAME, "nodes": {}}
    _save_deployment(root, deployment)
    DeploymentAuthority.create(PrivateDirectory(root / "authority"),
                               deployment["deployment_id"], validity=30 * DAY)
    authority = _authority(root, "authority")
    authority.issue_main_server_credential(PrivateDirectory(root / "listener"),
                                           server_name=SERVER_NAME, validity=14 * DAY)
    _write_private(root / "ca.pem", authority.ca_certificate_pem(), 0o644)
    other_id = uuid4()
    _write_private(root / "other-authority.json",
                   json.dumps({"deployment_id": str(other_id)}).encode("ascii"))
    DeploymentAuthority.create(PrivateDirectory(root / "other-authority"), other_id,
                               validity=30 * DAY)
    private_directory(root / "nodes")
    ledger = _ledger(root)
    if with_nodes:
        for label in (NEGATIVE_LABELS if negatives_only else LABELS):
            key, key_pem = _new_key()
            digest = public_key_digest(key.public_key())
            if label == "other_ca":
                other = _authority(root, "other-authority")
                other_ledger_root = private_directory(root / "other-ledger")
                issued = _pair(_ledger(other_ledger_root), other, _csr(key), digest)
                ca_pem = authority.ca_certificate_pem()  # the client still trusts Main
            else:
                issued = _pair(ledger, authority, _csr(key), digest, activate=label != "unpaired")
                ca_pem = authority.ca_certificate_pem()
                if label == "revoked":
                    ledger.revoke(_Owner(), "poc15-owner", node_id=issued.node_id)
            deployment["nodes"][label] = issued.node_id
            _node_bundle(root, label, issued.node_id, issued.certificate_pem, key_pem, ca_pem)
    _save_deployment(root, deployment)
    return root


def node_key(directory):
    """Capture side: create a node key and CSR; the key never leaves this host."""
    from cryptography.hazmat.primitives import serialization
    from media_capture_agent.node_tls import build_enrollment_request, generate_node_key
    directory = private_directory(directory)
    key = generate_node_key()
    request = build_enrollment_request(key)
    _write_private(directory / "key.pem", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    _write_private(directory / "csr.pem", request.csr_pem, 0o644)
    return directory


def issue(root, csr_path, label="good"):
    """Main side: approve, redeem and activate a capture-host CSR as ``label``."""
    from cryptography import x509
    from app.cameras.remote_agent.node_ca import public_key_digest
    if label not in ("good", "revoked_live"):
        raise MaterialsError("only positive labels can be issued from a CSR")
    root = Path(root).resolve()
    deployment = load_deployment(root)
    if label in deployment["nodes"] and label != "revoked_live":
        raise MaterialsError("label already issued")
    bundle = root / "nodes" / label
    if bundle.exists():
        if label != "revoked_live":
            raise MaterialsError("label already issued")
        import shutil
        shutil.rmtree(bundle)  # a fresh revoked_live per run; the old one stays revoked
    csr_pem = Path(csr_path).read_bytes()
    if len(csr_pem) > 8192:
        raise MaterialsError("csr too large")
    digest = public_key_digest(x509.load_pem_x509_csr(csr_pem).public_key())
    authority = _authority(root, "authority")
    issued = _pair(_ledger(root), authority, csr_pem, digest)
    deployment["nodes"][label] = issued.node_id
    _save_deployment(root, deployment)
    return _node_bundle(root, label, issued.node_id, issued.certificate_pem, None,
                        authority.ca_certificate_pem())


def replace_loopback_node(root, label):
    """Loopback only: give ``label`` a fresh paired key (the old one stays revoked)."""
    import shutil
    from app.cameras.remote_agent.node_ca import public_key_digest
    if label != "revoked_live":
        raise MaterialsError("only revoked_live is replaced between runs")
    root = Path(root).resolve()
    deployment = load_deployment(root)
    bundle = root / "nodes" / label
    if bundle.exists():
        shutil.rmtree(bundle)
    key, key_pem = _new_key()
    authority = _authority(root, "authority")
    issued = _pair(_ledger(root), authority, _csr(key), public_key_digest(key.public_key()))
    deployment["nodes"][label] = issued.node_id
    _save_deployment(root, deployment)
    _node_bundle(root, label, issued.node_id, issued.certificate_pem, key_pem,
                 authority.ca_certificate_pem())


def revoke(root, label):
    deployment = load_deployment(root)
    _ledger(root).revoke(_Owner(), "poc15-owner", node_id=deployment["nodes"][label])


def listener_paths(root):
    root = Path(root).resolve()
    from app.cameras.remote_agent.node_ca import PrivateDirectory, listener_material
    material = listener_material(PrivateDirectory(Path(root) / "listener"))
    return material.certificate_path, material.key_path
