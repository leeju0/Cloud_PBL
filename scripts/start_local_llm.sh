#!/usr/bin/env bash
set -euo pipefail

MODEL_PATH="${LLM_MODEL_PATH:-/data/LLM_model/gemma4/gemma-4-12b-it-IQ4_NL.gguf}"
GPU_DEVICE="${LLM_DEVICE:-2}"
PORT="${LLM_PORT:-8080}"
HOST="${LLM_HOST:-127.0.0.1}"
LLAMA_SERVER="${LLAMA_SERVER:-llama-server}"

if ! command -v "${LLAMA_SERVER}" >/dev/null 2>&1 && [[ "${LLAMA_SERVER}" == "llama-server" ]]; then
  if [[ -x "/data/LLM_model/llama.cpp/build/bin/llama-server" ]]; then
    LLAMA_SERVER="/data/LLM_model/llama.cpp/build/bin/llama-server"
  fi
fi

if [[ ! -f "${MODEL_PATH}" ]]; then
  echo "Model not found: ${MODEL_PATH}" >&2
  exit 1
fi
if ! command -v "${LLAMA_SERVER}" >/dev/null 2>&1; then
  echo "llama-server is required; install a llama.cpp build with GGUF support." >&2
  exit 1
fi

export CUDA_VISIBLE_DEVICES="${GPU_DEVICE}"
echo "Starting local LLM with physical GPU ${GPU_DEVICE}; process-visible device is logical GPU 0."
exec "${LLAMA_SERVER}" \
  --model "${MODEL_PATH}" \
  --host "${HOST}" \
  --port "${PORT}" \
  --ctx-size "${LLM_CONTEXT_SIZE:-4096}" \
  --n-gpu-layers "${LLM_GPU_LAYERS:--1}" \
  --reasoning off \
  --reasoning-format none \
  --alias "${LLM_MODEL_NAME:-gemma4}"
