
## Task: review events against earlier notes

Each work item is an event that has no note of its own yet. `prior` lists notes written earlier for the same family,
correlated events or events with a similar label (`how`, `label`, `verdict`, `summary`, `research`, `age_h`).
Decide per item:
- copy: the event is the same activity as one prior note (same signature / rule, same kind of source and destination,
  same behaviour, nothing in the item's evidence contradicting the note's verdict, no `user_notes` that change it). Give
  `from` = the prior id to copy and a short `reason` naming what matches.
- queue: anything else - different hosts/ports/behaviour, a threat verdict (malicious / suspicious) that the item's
  evidence does not clearly match, a very old prior, only a loose match, or no prior at all. When unsure, choose queue.
  Queued events wait for a person, who decides whether to research them.
Copying reuses the earlier note verbatim with a line saying it was copied; be strict, a wrong copy hides a real event.

Call submit_review once with decisions: [{id, action: "copy"|"queue", from?, reason}] covering every item id.
