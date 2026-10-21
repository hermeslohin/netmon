## Task: research notes for dashboard events

Below is a batch of work items from the dashboard (alerts, findings, IDS signatures, endpoint host findings, gateway
events...). Each has an `id`, its evidence, the existing research `note` (if any), `user_notes` (the owner's notes on
that event - authoritative), `host_notes` for the internal hosts involved, `internet_notes` for external IPs, and `related` candidate links between events
(proposed by a script; the local model's verdict may be included).

For each item WITHOUT a note, and for items whose existing note is now contradicted by the evidence, write a research
note:
- verdict: malicious | suspicious | needs-review | benign | expected
- priority: Investigate | Review | Info
- summary: one or two plain-language sentences - what it is and what to do
- research: what you checked and found (specific peers, domains, ports, times from Elasticsearch; what the sources say;
  why that leads to the verdict), citing [n] ids from `cite`
- links: only pages you fetched (this run or an earlier run's ledger), as [{title, url}]

Type-specific guidance:
- Suricata severity 1-2 (`ids|...` with suricata.severity 1 or 2): pull sample alerts (rule sid/rev, payload / http /
  dns / tls fields, the flow's Zeek conn record), identify both endpoints, read the rule's documentation and any CVE it
  names, decide whether it is a true positive. Give the sid and exact hosts/ports/times. Refresh the note when the
  evidence changed (new hosts or ports, count up sharply, seen again after a gap).
- Gateway events (`gw|...`): correlate with Suricata and Zeek for the same IPs and times (was it answered, how many
  bytes), check source IPs against the snapshot's threat intel and reputation sources, identify the destination device;
  for non-threat events (WAN latency, loops, firmware) say what happened and whether action is needed.
- Endpoint host findings (`hf|...`): investigate on the endpoint with logs-endpoint.events.*, osquery results,
  system auth/syslog and Fleet agent status: which process, user, parent, command line and time; whether it lines up
  with a package install, update, cron job or admin session; what the vendor docs say. Findings with one shared cause
  may share research text, but each gets its own note with its own id.

Every es_search is kept as a clickable Kibana artifact of the notes and links of its batch. Pass `for_ids` (the work item ids the
search is about) so it is attached only to those notes.

Also review each item's `related` candidates: is each pair genuinely the same activity or incident? Give
{a, b, related: true|false, confidence 0-1, reason} - prioritise pairs the local model has not reviewed or that you
disagree with.

Record durable facts about devices as host_notes so later runs and the chat do not re-research them:
[{ip | mac | host, category: role | baseline | behavior | decision | risk | config | watch | other, text, id?}] - what a
device is and does, what is normal for it and why, decisions about recurring behaviour, weaknesses, things to watch.
Never per-run numbers. Update an existing AI note (pass its id) instead of adding a near-duplicate; never edit or delete
notes whose author starts with `user:`. host_notes_delete: ids of AI notes that are now wrong.

External (public) IPs: items carry `internet_notes` ({ip: [...]}) - what is already known about those addresses; weigh them
when deciding benign / expected. When you learn something durable about an external IP (owner / ASN, what service it is, why
this network talks to it, or why it is a concern), record it as a host_note with `ip` set to that public address (same
fields, one short factual note per IP; update the existing one by id rather than adding another). They are listed on the
dashboard's Network > Internet notes page.

Finish by calling submit_notes once with notes, links, host_notes and host_notes_delete (use the exact id strings from
the batch). If it reports rejected ids, fix them and call it again.
