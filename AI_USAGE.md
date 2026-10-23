# AI usage: dsc26-cyb-w02

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

- AI pair-programming assistant (Qoder) used for: drafting `tmcheck/core.py` from the README spec,
  writing `tmcheck/__main__.py`, and drafting the
  eleven new threats (T27–T38) in `models/rawaj_scoring.yaml`.
- The AI also ran the public tests and edge-case scripts locally.

## What AI got wrong

1. In `coverage_gaps`, the AI first wrote `elements.get(ref, {}).get("is_log")` but put a wrong
   variable into `applicable` .
   Noticed while cleaning up the generated code before running tests: a log store that is in scope would
   silently miss its required `R` gap. Re-read of the README ("plus R when is_log") confirmed the fix.

2. The AI initially wrote the new threat titles with repeated words like "A ... a ...". The README
   only requires uniqueness across the file, but at the design review repeated articles looked
   machine-generated, so the titles were rewritten to drop the repeats.

## In my own words

1. Why does a data store have no Spoofing threats in STRIDE per element, and where does that threat
   go instead?

   becuse the data store is just a box that sit and save the data, he dont talk to nobody so he can't
   pretend to be someone else. spoofing is about the identity of who is sending, not the storage.
   so this threat go on the flow or the external entity that connect to the store, like somthing
   pretend he is the gateway that write inside the db.

2. Which of your eleven new threats would you fix first, and why that one?

   i fix T38 first, the debug endpoint that dump the account details from feature_store. becuse his
   score is the highst between my new threats, and also the fix is small and fast,
   just close the endpoint or put auth on it, so i take big benifit from little work.
