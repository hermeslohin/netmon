#!/bin/bash
# Start the netmon LLM broker under Hermes' own Python runtime (it needs Hermes' provider credentials).
set -eu
NM=$(cd "$(dirname "$0")" && pwd)
PY=$(~/.local/bin/hermes --print-runtime-command | /usr/bin/python3 -c "import json,sys;print(json.load(sys.stdin)[0])")
export HERMES_HOME=${HERMES_HOME:-$HOME/.hermes}
exec "$PY" -I -c "import os, sys, runpy; sys.path.insert(0, os.path.expanduser('~/.hermes/hermes-agent')); sys._hermes_pin_default_home = True; import hermes_bootstrap; sys.argv = ['llm_broker.py']; runpy.run_path('$NM/llm_broker.py', run_name='__main__')"
