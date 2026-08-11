"""Verify the PDF backend's fixed staged-artifact publication contract.

PDF is the first Validibot backend that may publish six declared artifact
outputs from one attempt. These tests ensure similarly named selections retain
distinct roles, filenames, media types, and stable publication order.
"""

from types import SimpleNamespace

from validator_backends.pdf import main as pdf_main
from validator_backends.pdf.engine import StagedArtifact


def test_all_six_artifacts_keep_distinct_fixed_output_identities(
    monkeypatch,
    tmp_path,
) -> None:
    """One attempt must not collapse selected XML/JSON or other optional ports."""
    calls = []

    def fake_upload_file_artifact(**kwargs):
        calls.append(kwargs)
        return kwargs["artifact_type"]

    monkeypatch.setattr(
        pdf_main,
        "upload_file_artifact",
        fake_upload_file_artifact,
    )
    envelope = SimpleNamespace(context=SimpleNamespace(execution_bundle_uri="gs://bucket/attempt"))
    payloads = {}
    for contract_key in pdf_main._ARTIFACT_CONTRACT:
        path = tmp_path / contract_key
        path.write_bytes(contract_key.encode())
        payloads[contract_key] = StagedArtifact.from_path(path)

    artifacts = pdf_main._upload_artifacts(envelope, payloads)

    expected_roles = list(pdf_main._ARTIFACT_CONTRACT)
    assert artifacts == expected_roles
    assert [call["artifact_type"] for call in calls] == expected_roles
    assert len({call["filename"] for call in calls}) == 6
    assert len({call["artifact_type"] for call in calls}) == 6
    assert all(call["source_path"].is_file() for call in calls)
    assert all(call["expected_sha256"] for call in calls)
