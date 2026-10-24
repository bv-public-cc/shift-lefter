import json
from collections import defaultdict

from shift_lefter import operational_corpus


def test_operational_corpus_is_repository_grouped_diverse_and_content_free(
    tmp_path, monkeypatch
):
    research = tmp_path / "research"
    monkeypatch.setattr(
        operational_corpus.experiment, "_research_root", lambda: research
    )
    monkeypatch.setattr(
        operational_corpus.experiment, "_assert_outside_git", lambda _path: None
    )

    summary = operational_corpus.generate(count=600, seed=170031)
    root = research / "raw" / operational_corpus.SET_NAME
    truth = json.loads((root / "ground_truth.json").read_text())
    canaries = json.loads((root / "canary_index.json").read_text())["canaries"]
    serialized_truth = json.dumps(truth)

    assert summary["artifact_count"] == 600
    assert truth["positive_count"] == 200
    assert truth["negative_count"] == 400
    assert truth["repo_count"] == 30
    assert truth["repository_grouped_holdout"] is True
    assert len({item["category"] for item in truth["records"] if item["label"]}) == 16
    assert (
        len({item["category"] for item in truth["records"] if not item["label"]}) == 16
    )
    assert not any(canary in serialized_truth for canary in canaries)

    partitions_by_repo = defaultdict(set)
    labels_by_channel = defaultdict(set)
    for record in truth["records"]:
        partitions_by_repo[record["repo_id"]].add(record["partition"])
        labels_by_channel[record["channel"]].add(record["label"])
        assert (root / "artifacts" / record["filename"]).is_file()
    assert all(len(partitions) == 1 for partitions in partitions_by_repo.values())
    assert all(labels == {0, 1} for labels in labels_by_channel.values())


def test_operational_corpus_refuses_overwrite(tmp_path, monkeypatch):
    research = tmp_path / "research"
    monkeypatch.setattr(
        operational_corpus.experiment, "_research_root", lambda: research
    )
    monkeypatch.setattr(
        operational_corpus.experiment, "_assert_outside_git", lambda _path: None
    )
    operational_corpus.generate(count=600, seed=170031)

    try:
        operational_corpus.generate(count=600, seed=170031)
    except RuntimeError as exc:
        assert "refusing to overwrite" in str(exc)
    else:
        raise AssertionError("operational corpus overwrite was not rejected")
