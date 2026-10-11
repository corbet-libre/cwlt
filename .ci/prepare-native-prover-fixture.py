"""Authenticate the original already-retained public extension proving fixture."""
import hashlib
import json
import os
from pathlib import Path

artifact_root = Path(os.environ["ARTIFACT_ROOT"])
if not artifact_root.is_absolute() or artifact_root.name != "release-artifacts":
    raise SystemExit("Expected the original product artifact root")
shared = artifact_root.parent.parent
if shared.name != "ccid-cached":
    raise SystemExit("Expected the original shared product cache mount")
# Original CBLC product retention location, not a download or a new cache format.
source = shared / "08a9478e457e604aa31f9a54/release-artifacts/gather-record-fixture"
source = source.resolve(strict=True)
pins = {
    "worker.json": (65536, "7270351d40c1ed49b1499ec82e59449e6d28ca715d5590485dee56e7ef757ff2"),
    "manifest.json": (65536, "f9481cd5933dff2a560ef08f2d710304c4a9fc6dee97c776176a6032669012ee"),
    "circuits.json": (64 * 1024 * 1024, "49b022b8356f0b331bcb5d8b2c86c14c619219d8e597c4abbd386ce98318b5e4"),
    "keys.json": (1024 * 1024, "e1533badd256e63b7817018ba59a5cd822f3e936a723d7f31bd85a49a6190ae0"),
    "setup/g1.dat": (128 * 1024 * 1024, "23d5e6ef4d511367e83c0d909911b7cdd33f0b324d4106d57eefdf50fac6a59d"),
    "setup/g2.dat": (128, "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f"),
}
for name, (maximum, expected) in pins.items():
    path = (source / name).resolve(strict=True)
    if not path.is_relative_to(source) or not path.is_file() or path.stat().st_size > maximum:
        raise SystemExit("Original fixture path or bound differs")
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while data := stream.read(1024 * 1024):
            count += len(data)
            if count > maximum:
                raise SystemExit("Original fixture grew past its bound")
            digest.update(data)
    if digest.hexdigest() != expected:
        raise SystemExit("Original retained fixture differs from its authenticated receipt")
receipt = json.loads((source / "worker.json").read_text())
manifest = json.loads((source / "manifest.json").read_text())
if receipt["sourceCommit"] != "d6014acbef63f4cd0929b20091884dd422421fc3" or (
    manifest["compiler"], manifest["backend"], manifest["accountingMode"], manifest["numPoints"]
) != ("1.0.0-beta.26", "5.0.0", "account-extension-v1", 2621440):
    raise SystemExit("Original producer or artifact contract differs")
Path("native-prover-fixture.json").write_text(json.dumps({
    "sourceCommit": receipt["sourceCommit"],
    "sourceArchiveSha256": receipt["sourceArchiveSha256"],
    "cargoLockSha256": receipt["cargoLockSha256"],
    "fixture": str(source), "files": {n: p[1] for n, p in pins.items()},
}, indent=2) + "\n")
print(source)
