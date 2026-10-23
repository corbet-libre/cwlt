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
source = shared / "08a9478e457e604aa31f9a54/release-artifacts/a8a4689889a33c8edd0186ba64f5d65bd2a47e97/artifact-conformance"
source = source.resolve(strict=True)
pins = {
    "worker-receipt.json": (65536, "ab51e6cd6af6cbe633cb6a3c89795ee9015ff02ca87fb198a5b547e4c32617b0"),
    "manifest.json": (65536, "73d26cccb5d835ab0101c3910d30c8e554c332e6514c69eab784a6abf9c7809d"),
    "circuits.json": (64 * 1024 * 1024, "5a24a6ae074c4e02e5673543a1b6e1027d1dd4a6ee64d71d83054495276f5806"),
    "keys.json": (1024 * 1024, "b8f2d00902b313ef6a920cc2f50ef9ca43a6a6f6816538564659980a7dc52682"),
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
if receipt["sourceCommit"] != "e5514337959c4aacb3e9d7f678e3f45898b61061" or (
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
