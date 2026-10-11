"""Select the actual owned example executable from original Cargo build output."""
import hashlib
import json
from pathlib import Path

records = [json.loads(line) for line in Path("native-prover-build.json").read_text().splitlines() if line]
selected = [r for r in records if r.get("reason") == "compiler-artifact" and
            r.get("target", {}).get("name") == "cwlt-account-worker" and
            r.get("target", {}).get("kind") == ["example"] and r.get("executable")]
if len(selected) != 1 or Path(selected[0]["manifest_path"]).resolve() != Path("engine/Cargo.toml").resolve():
    raise SystemExit("Expected exactly one actual owned engine worker")
worker = Path(selected[0]["executable"])
if not worker.is_absolute() or not worker.is_file() or worker.stat().st_size > 512 * 1024 * 1024:
    raise SystemExit("Actual owned worker path or allocation bound differs")
digest = hashlib.sha256()
with worker.open("rb") as stream:
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
Path("native-prover-worker.json").write_text(json.dumps({"executable": str(worker), "sha256": digest.hexdigest()}, indent=2) + "\n")
print(worker)
