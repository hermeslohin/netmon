#!/usr/bin/env bash
# Decision model server for the correlation review: a "System One" decision model (Cloudflare clef) on llama.cpp's
# llama-server, which serves the System One API (/v1/systemone, needs logits). A plain chat server cannot run it.
# llama-server is taken from CLEF_SERVER, else PATH, else an LM Studio install's bundled llama.cpp runtime;
# the model from CLEF_GGUF, else CLEF_MODELS_DIR, ~/models or an LM Studio model folder.
# Settings: AI review > Decision model server (netmon database, document clef_server; read via clef_server.py env).
# Environment overrides win: CLEF_GGUF (model file), CLEF_SERVER (llama-server binary), CLEF_PORT (8091), CLEF_CTX,
# CLEF_PARALLEL, CLEF_BATCH. A decision model reads its whole input in one micro-batch: -b/-ub must cover the longest
# state (the default 512 rejects anything longer with "input too large", which the client sees as a hang).
set -euo pipefail
NM="$(cd "$(dirname "$0")" && pwd)"
eval "$(/usr/bin/python3 "$NM/clef_server.py" env 2>/dev/null || true)"
PORT="${CLEF_PORT:-8091}"
BATCH="${CLEF_BATCH:-8192}"
# full clef (27B) by default - more accurate on links than clef-flash (9B), ~3x slower; flash only as a fallback
DIRS="${CLEF_MODELS_DIR:+${CLEF_MODELS_DIR//:/ }} $HOME/models $HOME/.lmstudio/models"
find_gguf() { for d in $DIRS; do find "$d" -maxdepth 3 -name "$1" 2>/dev/null; done | sort | tail -1; }
GGUF="${CLEF_GGUF:-$(find_gguf 'Cloudflare_clef-Q*.gguf')}"
GGUF="${GGUF:-$(find_gguf '*clef-flash-Q*.gguf')}"
SRV="${CLEF_SERVER:-$(command -v llama-server || true)}"
SRV="${SRV:-$(ls -1d "$HOME"/.lmstudio/extensions/backends/llama.cpp-linux-*-cuda*/llama-server 2>/dev/null | sort -V | tail -1)}"
[ -n "$GGUF" ] && [ -f "$GGUF" ] || { echo "clef.sh: no clef GGUF found (see AI review > Decision model server > Stand-up instructions)" >&2; exit 2; }
[ -n "$SRV" ] && [ -x "$SRV" ] || { echo "clef.sh: no llama-server found (put a llama.cpp llama-server with System One support on PATH, or set CLEF_SERVER)" >&2; exit 2; }
export LD_LIBRARY_PATH="$(dirname "$SRV")${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
echo "clef.sh: $SRV -m $GGUF on 127.0.0.1:$PORT (ctx ${CLEF_CTX:-32768}, parallel ${CLEF_PARALLEL:-4}, batch $BATCH)" >&2
exec "$SRV" -m "$GGUF" --host 127.0.0.1 --port "$PORT" -ngl 99 -c "${CLEF_CTX:-32768}" --parallel "${CLEF_PARALLEL:-4}" -b "$BATCH" -ub "$BATCH" --alias "$(basename "$GGUF" .gguf)"
