
import hashlib

from evaluation.manifest import (
    sha256_file,
    verify_manifest,
)


def test_sha256_file(tmp_path):
    path = tmp_path / "example.txt"
    path.write_text(
        "AgentSecBench",
        encoding="utf-8"
    )

    expected = hashlib.sha256(
        b"AgentSecBench"
    ).hexdigest()

    assert sha256_file(path) == expected


def test_manifest_matching_file(
    tmp_path,
    monkeypatch
):
    from evaluation import manifest

    monkeypatch.setattr(
        manifest,
        "ROOT",
        tmp_path
    )

    path = tmp_path / "sample.txt"
    path.write_text(
        "original",
        encoding="utf-8"
    )

    data = {
        "file_hashes": {
            "sample.txt": sha256_file(path)
        }
    }

    result = verify_manifest(data)

    assert result["valid"] is True
    assert result["mismatches"] == []
    assert result["missing"] == []


def test_manifest_modified_file(
    tmp_path,
    monkeypatch
):
    from evaluation import manifest

    monkeypatch.setattr(
        manifest,
        "ROOT",
        tmp_path
    )

    path = tmp_path / "sample.txt"
    path.write_text(
        "original",
        encoding="utf-8"
    )

    data = {
        "file_hashes": {
            "sample.txt": sha256_file(path)
        }
    }

    path.write_text(
        "modified",
        encoding="utf-8"
    )

    result = verify_manifest(data)

    assert result["valid"] is False
    assert "sample.txt" in (
        result["mismatches"]
    )


def test_manifest_missing_file(
    tmp_path,
    monkeypatch
):
    from evaluation import manifest

    monkeypatch.setattr(
        manifest,
        "ROOT",
        tmp_path
    )

    data = {
        "file_hashes": {
            "missing.txt": "example"
        }
    }

    result = verify_manifest(data)

    assert result["valid"] is False
    assert "missing.txt" in (
        result["missing"]
    )
