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
source = shared / "08a9478e457e604aa31f9a54/release-artifacts/8d631b902d52893dd9480cf80aa75efce66a928a/artifact-conformance"
source = source.resolve(strict=True)
pins = {
    "worker-receipt.json": (65536, "ab51e6cd6af6cbe633cb6a3c89795ee9015ff02ca87fb198a5b547e4c32617b0"),
    "manifest.json": (65536, "079028ca859d90a75b51632f0628fabb9a5bc4311615f915ee287ba8bba624f0"),
    "circuits.json": (64 * 1024 * 1024, "487b5bc4cd3ea220d02e27efb449847472d6ff827bacf9a0e5f9d483001b53fc"),
    "keys.json": (1024 * 1024, "0b4dbcd0fb3e3bf29cd213fc138183560a9adb52f05e64dc5c4b2c0590a7a359"),
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
