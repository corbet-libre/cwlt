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
source = shared / "08a9478e457e604aa31f9a54/release-artifacts/660e913088aa2d4b2a510143e66be31c9daed963/artifact-conformance"
source = source.resolve(strict=True)
pins = {
    "worker-receipt.json": (65536, "c24bd328405e0192423fc0ed925b08ca7d4992bdb4ac3c5e8ad839605df5cf10"),
    "manifest.json": (65536, "f935b80363c34496463b3b7f2a3270add37f52696e14d048c4c4c96aa478d228"),
    "circuits.json": (64 * 1024 * 1024, "d05e0c72570ab4d5fcc0ab647c94fb417d03dcc15ab0f202a7a663a5512de0cb"),
    "keys.json": (1024 * 1024, "93652968e257953ce691e39e3da881eb098622db666dbb2c2cd219eabbbc4c1d"),
    "setup/g1.dat": (128 * 1024 * 1024, "23d5e6ef4d511367e83c0d909911b7cdd33f0b324d4106d57eefdf50fac6a59d"),
    "setup/g2.dat": (128, "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f"),
}
actual = {}
mismatched = False
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
    actual[name] = digest.hexdigest()
    if digest.hexdigest() != expected:
        mismatched = True
if mismatched:
    for name, value in actual.items():
        print(f"CWLT-FIXTURE-DIGEST {name} {value}", file=__import__("sys").stderr)
    raise SystemExit("Original retained fixture differs from its authenticated receipt")
receipt = json.loads((source / "worker-receipt.json").read_text())
manifest = json.loads((source / "manifest.json").read_text())
if receipt["sourceCommit"] != "829489a47cb3b2798830921591416b73f09ccafa" or (
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
