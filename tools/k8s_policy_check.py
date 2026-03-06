#!/usr/bin/env python3
import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Finding:
    severity: str  # ERROR | WARN | INFO
    rule_id: str
    message: str
    path: str | None = None


def add(findings: list[Finding], severity: str, rule_id: str, message: str, path: Path | None = None) -> None:
    findings.append(
        Finding(
            severity=severity,
            rule_id=rule_id,
            message=message,
            path=str(path.relative_to(REPO_ROOT)) if path else None,
        )
    )


def load_manifest(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON ({path}): {exc}") from exc


def check_manifests(findings: list[Finding]) -> None:
    manifest_dir = REPO_ROOT / "k8s" / "manifests"
    if not manifest_dir.exists():
        add(findings, "WARN", "k8s.missing", "k8s/manifests is missing; add minimal secure-default manifests.")
        return

    manifests = sorted(manifest_dir.glob("*.json"))
    if not manifests:
        add(findings, "WARN", "k8s.empty", "No JSON manifests found under k8s/manifests.", manifest_dir)
        return

    required_kinds = {"Namespace", "NetworkPolicy", "ResourceQuota", "LimitRange", "PodDisruptionBudget"}
    seen_kinds: set[str] = set()

    for m in manifests:
        try:
            doc = load_manifest(m)
        except ValueError as exc:
            add(findings, "ERROR", "k8s.invalid_json", str(exc), m)
            continue

        kind = doc.get("kind")
        api_version = doc.get("apiVersion")
        meta = doc.get("metadata") or {}
        name = meta.get("name")
        if not kind or not api_version or not name:
            add(findings, "ERROR", "k8s.required_fields", "Manifest must include apiVersion, kind, metadata.name.", m)
            continue

        seen_kinds.add(kind)

        if kind == "NetworkPolicy":
            spec = doc.get("spec") or {}
            if spec.get("podSelector") is None or spec.get("policyTypes") is None:
                add(findings, "ERROR", "k8s.netpol.shape", "NetworkPolicy should include spec.podSelector and spec.policyTypes.", m)
            if spec.get("ingress") is None and spec.get("egress") is None:
                add(findings, "WARN", "k8s.netpol.default_deny", "Consider explicit default-deny by setting empty ingress/egress lists.", m)

    missing = sorted(required_kinds - seen_kinds)
    if missing:
        add(findings, "WARN", "k8s.kinds_missing", f"Missing recommended kinds: {', '.join(missing)}", manifest_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline Kubernetes manifest policy checks (JSON).")
    parser.add_argument("--out", default="artifacts/k8s_policy_findings.json")
    args = parser.parse_args()

    findings: list[Finding] = []
    check_manifests(findings)

    report = {"summary": {"errors": sum(1 for f in findings if f.severity == "ERROR")}, "findings": [asdict(f) for f in findings]}
    out_path = (REPO_ROOT / args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return 1 if report["summary"]["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

