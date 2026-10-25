# Model Notices

The trained review experiment uses these upstream base models:

- IBM Granite 4.1 3B Base: <https://huggingface.co/ibm-granite/granite-4.1-3b-base>
- Qwen3 4B Base: <https://huggingface.co/Qwen/Qwen3-4B-Base>

Both upstream repositories identify the model license as Apache License 2.0.
The experiment records the exact downloaded revision in each training manifest.
The locally trained adapter weights and packaged LightGBM model are stored in
the private Nexus repository with SHA-256 checksums; they are not committed to
Git.
