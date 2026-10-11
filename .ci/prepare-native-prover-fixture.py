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
# Audited CBLC artifact-conformance retention (Barretenberg 5.2.1, one prover version
# across server and wallet); not a download or a new cache format.
source = shared / "08a9478e457e604aa31f9a54/release-artifacts/4a933fc30a8f8d9e1a5801ed2f826a82efd9b861/artifact-conformance"
source = source.resolve(strict=True)
pins = {
    "worker-receipt.json": (65536, "0b2c57f19c1440aaa55b62b3f27a57c96b8baec38a266ab291e719cc9a3b638d"),
    "manifest.json": (65536, "81aec00155f28e7b1d064adeb893593e4bedae01bd8334f80bf0c65ce91c8efc"),
    "circuits.json": (64 * 1024 * 1024, "b1bb892081b56e441211370c24e8f4371d053115e79e9a0011082131c79d375c"),
    "keys.json": (1024 * 1024, "3b0c627844f05d0c9f295a987a4125d21dfb693498614d11f09a1119c5c09993"),
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
receipt = json.loads((source / "worker-receipt.json").read_text())
manifest = json.loads((source / "manifest.json").read_text())
if receipt["sourceCommit"] != "d6014acbef63f4cd0929b20091884dd422421fc3" or (
    manifest["compiler"], manifest["backend"], manifest["accountingMode"], manifest["numPoints"]
) != ("1.0.0-beta.26", "5.2.1", "account-extension-v1", 2621440):
    raise SystemExit("Original producer or artifact contract differs")
Path("native-prover-fixture.json").write_text(json.dumps({
    "sourceCommit": receipt["sourceCommit"],
    "sourceArchiveSha256": receipt["sourceArchiveSha256"],
    "cargoLockSha256": receipt["cargoLockSha256"],
    "fixture": str(source), "files": {n: p[1] for n, p in pins.items()},
}, indent=2) + "\n")
print(source)
