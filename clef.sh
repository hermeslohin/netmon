#!/usr/bin/env bash
# Decision model server for the correlation review: Cloudflare clef-flash (a "System One" decision model) on
# llama.cpp's llama-server, which is the only runtime that serves it (/v1/systemone). LM Studio can load the GGUF
# but cannot run it ("context does not support logits computation"), so this uses LM Studio's bundled llama-server.
# Overrides: CLEF_GGUF (model file), CLEF_SERVER (llama-server binary), CLEF_PORT (8091), CLEF_CTX, CLEF_PARALLEL.
set -euo pipefail
PORT="${CLEF_PORT:-8091}"
GGUF="${CLEF_GGUF:-$(ls -1 "$HOME"/.lmstudio/models/*/*clef-flash*GGUF/*clef-flash-Q*.gguf 2>/dev/null | sort | tail -1)}"
SRV="${CLEF_SERVER:-$(ls -1d "$HOME"/.lmstudio/extensions/backends/llama.cpp-linux-*-cuda*/llama-server 2>/dev/null | sort -V | tail -1)}"
[ -n "$GGUF" ] && [ -f "$GGUF" ] || { echo "clef.sh: no clef-flash GGUF found (set CLEF_GGUF)" >&2; exit 2; }
[ -n "$SRV" ] && [ -x "$SRV" ] || { echo "clef.sh: no llama-server found (set CLEF_SERVER)" >&2; exit 2; }
export LD_LIBRARY_PATH="$(dirname "$SRV")${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
echo "clef.sh: $SRV -m $GGUF on 127.0.0.1:$PORT" >&2
exec "$SRV" -m "$GGUF" --host 127.0.0.1 --port "$PORT" -ngl 99 -c "${CLEF_CTX:-32768}" --parallel "${CLEF_PARALLEL:-4}" --alias clef-flash
