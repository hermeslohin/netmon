#!/bin/bash
# Hermes cron (no_agent): 15-minute urgent watcher. Prints alerts only when something new and serious happened;
# alerts are also stored for the dashboard + Web Push.
exec /usr/bin/python3 "$HOME/.hermes/netmon/watch.py"
