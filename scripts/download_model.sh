#!/usr/bin/env bash
# Downloads the Tier 2 classifier: protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0), ONNX build (~740 MB).
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)/models/prompt-injection-deberta-v3"
mkdir -p "$DIR"
for f in config.json tokenizer.json special_tokens_map.json tokenizer_config.json added_tokens.json spm.model model.onnx; do
  echo "downloading $f"
  curl -fsSL -o "$DIR/$f" "https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/$f"
done
echo "done: $DIR"
