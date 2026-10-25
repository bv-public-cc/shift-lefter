"""Train and run the three privacy-preserving review models."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import time
from pathlib import Path

from shift_lefter import experiment, trained_review

MODELS = {
    "granite": "ibm-granite/granite-4.1-3b-base",
    "qwen": "Qwen/Qwen3-4B-Base",
}
SEED = 410_041
MAX_LENGTH = 192


def _data_root() -> Path:
    return experiment._research_root() / "trained-data" / trained_review.DATASET_NAME


def _model_root(name: str) -> Path:
    root = experiment._research_root() / "models" / trained_review.DATASET_NAME / name
    experiment._assert_outside_git(root)
    return root


def _read(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def _write_predictions(
    name: str,
    split: str,
    rows: list[dict],
    probabilities: list[float],
    elapsed: float,
) -> dict:
    root = _model_root(name)
    destination = root / f"{split}-predictions.jsonl"
    if destination.exists():
        raise RuntimeError(f"refusing to overwrite predictions: {destination}")
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        for row, probability in zip(rows, probabilities, strict=True):
            handle.write(
                json.dumps(
                    {
                        "artifact_id": row["artifact_id"],
                        "secret_probability": round(float(probability), 9),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
    result = {
        "model": name,
        "split": split,
        "sample_count": len(rows),
        "total_inference_seconds": round(elapsed, 6),
        "mean_seconds_per_file": round(elapsed / len(rows), 9),
        "predictions_sha256": experiment._sha256_file(destination),
    }
    experiment._write_json(root / f"{split}-prediction-summary.json", result)
    return result


def _tree_hash(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(item.relative_to(path).as_posix().encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(item.read_bytes()).digest())
    return digest.hexdigest()


def _provenance() -> dict:
    from importlib.metadata import PackageNotFoundError, version

    packages = {}
    for name in (
        "accelerate",
        "lightgbm",
        "peft",
        "scikit-learn",
        "torch",
        "transformers",
    ):
        try:
            packages[name] = version(name)
        except PackageNotFoundError:
            continue
    return {
        "training_code_sha256": experiment._sha256_file(Path(__file__)),
        "feature_code_sha256": experiment._sha256_file(
            Path(trained_review.__file__).resolve()
        ),
        "training_features_sha256": experiment._sha256_file(
            _data_root() / "train.jsonl"
        ),
        "software_versions": packages,
    }


def _training_history(trainer) -> list[dict]:
    allowed = {"epoch", "grad_norm", "learning_rate", "loss", "step", "train_loss"}
    return [
        {
            key: value
            for key, value in entry.items()
            if key in allowed and isinstance(value, (int, float))
        }
        for entry in trainer.state.log_history
    ]


def train_lightweight() -> dict:
    import joblib
    from lightgbm import LGBMClassifier
    from sklearn.feature_extraction import DictVectorizer

    root = _model_root("lightgbm")
    if root.exists():
        raise RuntimeError("refusing to overwrite the lightweight model")
    root.mkdir(parents=True, mode=0o700)
    rows = _read(_data_root() / "train.jsonl")
    vectorizer = DictVectorizer(sparse=True)
    features = vectorizer.fit_transform(row["features"] for row in rows)
    labels = [int(row["label"]) for row in rows]
    model = LGBMClassifier(
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=31,
        min_child_samples=40,
        subsample=0.9,
        colsample_bytree=0.9,
        class_weight="balanced",
        random_state=SEED,
        n_jobs=max(1, (os.cpu_count() or 2) // 2),
        verbosity=-1,
    )
    started = time.perf_counter()
    model.fit(features, labels)
    elapsed = time.perf_counter() - started
    artifact = root / "model.joblib"
    joblib.dump({"vectorizer": vectorizer, "model": model}, artifact)
    result = {
        "model": "lightgbm",
        "implementation": "lightgbm.LGBMClassifier",
        "input_version": trained_review.MODEL_INPUT_VERSION,
        "seed": SEED,
        "training_sample_count": len(rows),
        "training_seconds": round(elapsed, 6),
        "artifact_sha256": experiment._sha256_file(artifact),
        **_provenance(),
    }
    experiment._write_json(root / "training-manifest.json", result)
    return result


def _tokenizer(model_id: str):
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(model_id, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    return tokenizer


class _TextDataset:
    def __init__(self, rows: list[dict], tokenizer) -> None:
        self.rows = rows
        self.tokenizer = tokenizer

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int) -> dict:
        row = self.rows[index]
        encoded = self.tokenizer(
            row["model_input"],
            truncation=True,
            max_length=MAX_LENGTH,
        )
        encoded["labels"] = int(row["label"])
        return encoded


def _base_model(model_id: str, tokenizer):
    import torch
    from transformers import AutoModelForSequenceClassification

    model = AutoModelForSequenceClassification.from_pretrained(
        model_id,
        num_labels=2,
        torch_dtype=torch.float16,
        attn_implementation="eager",
    )
    model.config.pad_token_id = tokenizer.pad_token_id
    model.config.use_cache = False
    return model


def _causal_label_ids(tokenizer) -> tuple[int, int]:
    zero = tokenizer.encode("0", add_special_tokens=False)
    one = tokenizer.encode("1", add_special_tokens=False)
    if len(zero) != 1 or len(one) != 1:
        raise RuntimeError("causal label values must each use one token")
    return zero[0], one[0]


class _CausalDataset:
    def __init__(self, rows: list[dict], tokenizer) -> None:
        self.rows = rows
        self.tokenizer = tokenizer
        self.label_ids = _causal_label_ids(tokenizer)

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int) -> dict:
        row = self.rows[index]
        prompt = row["model_input"] + "\nsecret_label="
        encoded = self.tokenizer(
            prompt,
            truncation=True,
            max_length=MAX_LENGTH - 1,
        )
        label_id = self.label_ids[int(row["label"])]
        input_ids = [*encoded["input_ids"], label_id]
        attention_mask = [*encoded["attention_mask"], 1]
        return {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "labels": [-100] * (len(input_ids) - 1) + [label_id],
        }


class _CausalCollator:
    def __init__(self, tokenizer) -> None:
        self.pad_token_id = tokenizer.pad_token_id

    def __call__(self, features: list[dict]) -> dict:
        import torch

        width = max(len(item["input_ids"]) for item in features)
        batch = {"input_ids": [], "attention_mask": [], "labels": []}
        for item in features:
            padding = width - len(item["input_ids"])
            batch["input_ids"].append(item["input_ids"] + [self.pad_token_id] * padding)
            batch["attention_mask"].append(item["attention_mask"] + [0] * padding)
            batch["labels"].append(item["labels"] + [-100] * padding)
        return {
            key: torch.tensor(value, dtype=torch.long) for key, value in batch.items()
        }


def train_causal_adapter(name: str, epochs: float) -> dict:
    import torch
    from peft import LoraConfig, TaskType, get_peft_model
    from transformers import AutoModelForCausalLM, Trainer, TrainingArguments

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required for adapter training")
    random.seed(SEED)
    torch.manual_seed(SEED)
    root = _model_root(name)
    if root.exists():
        raise RuntimeError(f"refusing to overwrite model directory: {root}")
    root.mkdir(parents=True, mode=0o700)
    model_id = MODELS[name]
    tokenizer = _tokenizer(model_id)
    label_ids = _causal_label_ids(tokenizer)
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.float16,
        attn_implementation="eager",
    )
    model.config.pad_token_id = tokenizer.pad_token_id
    model.config.use_cache = False
    model.gradient_checkpointing_enable()
    adapter = get_peft_model(
        model,
        LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=16,
            lora_alpha=32,
            lora_dropout=0.05,
            target_modules="all-linear",
            bias="none",
        ),
    )
    for parameter in adapter.parameters():
        if parameter.requires_grad:
            parameter.data = parameter.data.float()
    rows = _read(_data_root() / "train.jsonl")
    dataset = _CausalDataset(rows, tokenizer)
    work = root / "trainer-state"
    arguments = TrainingArguments(
        output_dir=str(work),
        num_train_epochs=epochs,
        per_device_train_batch_size=16,
        gradient_accumulation_steps=2,
        learning_rate=2e-4,
        warmup_ratio=0.03,
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        fp16=True,
        logging_steps=25,
        save_strategy="no",
        report_to="none",
        remove_unused_columns=False,
        dataloader_num_workers=2,
        seed=SEED,
    )
    trainer = Trainer(
        model=adapter,
        args=arguments,
        train_dataset=dataset,
        data_collator=_CausalCollator(tokenizer),
        processing_class=tokenizer,
    )
    started = time.perf_counter()
    output = trainer.train()
    elapsed = time.perf_counter() - started
    adapter_dir = root / "adapter"
    adapter.save_pretrained(adapter_dir, safe_serialization=True)
    tokenizer.save_pretrained(adapter_dir)
    result = {
        "model": name,
        "base_model": model_id,
        "base_revision": getattr(model.config, "_commit_hash", None),
        "training_method": "causal_label_adapter",
        "label_token_ids": list(label_ids),
        "input_version": trained_review.MODEL_INPUT_VERSION,
        "seed": SEED,
        "training_sample_count": len(rows),
        "epochs": epochs,
        "training_seconds": round(elapsed, 6),
        "training_loss": float(output.training_loss),
        "training_history": _training_history(trainer),
        "trainable_parameter_count": sum(
            parameter.numel()
            for parameter in adapter.parameters()
            if parameter.requires_grad
        ),
        "total_parameter_count": sum(
            parameter.numel() for parameter in adapter.parameters()
        ),
        "adapter_tree_sha256": _tree_hash(adapter_dir),
        **_provenance(),
    }
    experiment._write_json(root / "training-manifest.json", result)
    return result


def _predict_causal_adapter(
    name: str, rows: list[dict], batch_size: int
) -> tuple[list[float], float]:
    import torch
    from peft import PeftModel
    from torch.utils.data import DataLoader
    from transformers import AutoModelForCausalLM

    model_id = MODELS[name]
    adapter_dir = _model_root(name) / "adapter"
    tokenizer = _tokenizer(str(adapter_dir))
    zero_id, one_id = _causal_label_ids(tokenizer)
    base = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.float16,
        attn_implementation="eager",
    )
    base.config.pad_token_id = tokenizer.pad_token_id
    model = PeftModel.from_pretrained(base, adapter_dir)
    model.eval()
    model.to("cuda")
    prompts = [row["model_input"] + "\nsecret_label=" for row in rows]

    class PromptDataset:
        def __len__(self) -> int:
            return len(prompts)

        def __getitem__(self, index: int) -> str:
            return prompts[index]

    def collate(values: list[str]) -> dict:
        return tokenizer(
            values,
            padding=True,
            truncation=True,
            max_length=MAX_LENGTH - 1,
            return_tensors="pt",
        )

    loader = DataLoader(
        PromptDataset(),
        batch_size=batch_size,
        shuffle=False,
        num_workers=2,
        collate_fn=collate,
    )
    probabilities = []
    torch.cuda.synchronize()
    started = time.perf_counter()
    with torch.inference_mode():
        for batch in loader:
            batch = {key: value.to("cuda") for key, value in batch.items()}
            logits = model(**batch).logits
            positions = batch["attention_mask"].sum(dim=1) - 1
            selected = logits[
                torch.arange(logits.shape[0], device=logits.device), positions
            ]
            binary = torch.stack((selected[:, zero_id], selected[:, one_id]), dim=-1)
            probabilities.extend(
                torch.softmax(binary.float(), dim=-1)[:, 1].cpu().tolist()
            )
    torch.cuda.synchronize()
    return probabilities, time.perf_counter() - started


def train_adapter(name: str, epochs: float = 1.0) -> dict:
    if name == "granite":
        return train_causal_adapter(name, epochs)
    if name not in MODELS:
        raise ValueError(f"unsupported model: {name}")
    import torch
    from peft import LoraConfig, TaskType, get_peft_model
    from transformers import DataCollatorWithPadding, Trainer, TrainingArguments

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required for adapter training")
    random.seed(SEED)
    torch.manual_seed(SEED)
    root = _model_root(name)
    if root.exists():
        raise RuntimeError(f"refusing to overwrite model directory: {root}")
    root.mkdir(parents=True, mode=0o700)
    model_id = MODELS[name]
    tokenizer = _tokenizer(model_id)
    model = _base_model(model_id, tokenizer)
    model.gradient_checkpointing_enable()
    adapter = get_peft_model(
        model,
        LoraConfig(
            task_type=TaskType.SEQ_CLS,
            r=16,
            lora_alpha=32,
            lora_dropout=0.05,
            target_modules="all-linear",
            modules_to_save=["score"],
            bias="none",
        ),
    )
    for parameter in adapter.parameters():
        if parameter.requires_grad:
            parameter.data = parameter.data.float()
    rows = _read(_data_root() / "train.jsonl")
    dataset = _TextDataset(rows, tokenizer)
    work = root / "trainer-state"
    arguments = TrainingArguments(
        output_dir=str(work),
        num_train_epochs=epochs,
        per_device_train_batch_size=16,
        gradient_accumulation_steps=2,
        learning_rate=2e-4,
        warmup_ratio=0.03,
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        fp16=True,
        logging_steps=25,
        save_strategy="no",
        report_to="none",
        remove_unused_columns=False,
        dataloader_num_workers=2,
        seed=SEED,
    )
    trainer = Trainer(
        model=adapter,
        args=arguments,
        train_dataset=dataset,
        data_collator=DataCollatorWithPadding(
            tokenizer=tokenizer,
            pad_to_multiple_of=8,
        ),
        processing_class=tokenizer,
    )
    started = time.perf_counter()
    output = trainer.train()
    elapsed = time.perf_counter() - started
    adapter_dir = root / "adapter"
    adapter.save_pretrained(adapter_dir, safe_serialization=True)
    tokenizer.save_pretrained(adapter_dir)
    result = {
        "model": name,
        "base_model": model_id,
        "base_revision": getattr(model.config, "_commit_hash", None),
        "input_version": trained_review.MODEL_INPUT_VERSION,
        "seed": SEED,
        "training_sample_count": len(rows),
        "epochs": epochs,
        "training_seconds": round(elapsed, 6),
        "training_loss": float(output.training_loss),
        "training_history": _training_history(trainer),
        "trainable_parameter_count": sum(
            parameter.numel()
            for parameter in adapter.parameters()
            if parameter.requires_grad
        ),
        "total_parameter_count": sum(
            parameter.numel() for parameter in adapter.parameters()
        ),
        "adapter_tree_sha256": _tree_hash(adapter_dir),
        **_provenance(),
    }
    experiment._write_json(root / "training-manifest.json", result)
    return result


def _predict_lightweight(rows: list[dict]) -> tuple[list[float], float]:
    import joblib

    bundle = joblib.load(_model_root("lightgbm") / "model.joblib")
    started = time.perf_counter()
    features = bundle["vectorizer"].transform(row["features"] for row in rows)
    probabilities = bundle["model"].predict_proba(features)[:, 1].tolist()
    return probabilities, time.perf_counter() - started


def _predict_adapter(
    name: str, rows: list[dict], batch_size: int
) -> tuple[list[float], float]:
    if name == "granite":
        return _predict_causal_adapter(name, rows, batch_size)
    import torch
    from peft import PeftModel
    from torch.utils.data import DataLoader
    from transformers import DataCollatorWithPadding

    model_id = MODELS[name]
    adapter_dir = _model_root(name) / "adapter"
    tokenizer = _tokenizer(str(adapter_dir))
    base = _base_model(model_id, tokenizer)
    model = PeftModel.from_pretrained(base, adapter_dir)
    model.eval()
    model.to("cuda")
    dataset = _TextDataset(rows, tokenizer)
    loader = DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=2,
        collate_fn=DataCollatorWithPadding(
            tokenizer=tokenizer,
            pad_to_multiple_of=8,
        ),
    )
    probabilities = []
    torch.cuda.synchronize()
    started = time.perf_counter()
    with torch.inference_mode():
        for batch in loader:
            labels = batch.pop("labels", None)
            del labels
            batch = {key: value.to("cuda") for key, value in batch.items()}
            logits = model(**batch).logits
            probabilities.extend(
                torch.softmax(logits.float(), dim=-1)[:, 1].cpu().tolist()
            )
    torch.cuda.synchronize()
    return probabilities, time.perf_counter() - started


def predict(name: str, split: str, batch_size: int = 32) -> dict:
    if name not in {"lightgbm", *MODELS}:
        raise ValueError(f"unsupported model: {name}")
    source = (
        _data_root() / "setup-scanned.jsonl"
        if split == "setup"
        else _data_root() / "final.jsonl"
    )
    rows = _read(source)
    probabilities, elapsed = (
        _predict_lightweight(rows)
        if name == "lightgbm"
        else _predict_adapter(name, rows, batch_size)
    )
    return _write_predictions(name, split, rows, probabilities, elapsed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("lightweight")
    adapter = sub.add_parser("adapter")
    adapter.add_argument("--model", choices=sorted(MODELS), required=True)
    adapter.add_argument("--epochs", type=float, default=1.0)
    prediction = sub.add_parser("predict")
    prediction.add_argument(
        "--model", choices=["lightgbm", *sorted(MODELS)], required=True
    )
    prediction.add_argument("--split", choices=("setup", "final"), required=True)
    prediction.add_argument("--batch-size", type=int, default=32)
    args = parser.parse_args()
    result = (
        train_lightweight()
        if args.command == "lightweight"
        else (
            train_adapter(args.model, args.epochs)
            if args.command == "adapter"
            else predict(args.model, args.split, args.batch_size)
        )
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
