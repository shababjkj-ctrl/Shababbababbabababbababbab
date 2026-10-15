# Free Fire level-up bot (merged: Battle Royale + Lone Wolf)

Run: `python Main.py` (Procfile: `web: python Main.py`). Dashboard on `$PORT` (default 20337).

## Per-account behaviour
- Every account starts in **BR**. Level comes from GetLoginData (protobuf field 6) and is refreshed ~every 60 s.
- Level < 3 -> **Battle Royale**, 1 concurrent match. Level >= 3 -> **Lone Wolf**, up to 15 concurrent matches.
- The mode is read from that account's own level (`bot_state.get_account_level`) on every loop tick.
  On a change the account's old-mode UDP matches are cancelled, search/parse state is reset and the
  gateway socket is rebuilt in the new mode. Other accounts are never touched.
- Region is forced to **BD** (`FORCE_REGION`).

## What differs between the modes
- Search packet: `start_game_battle_royale` vs `start_game_lone_wolf` (different StartMatch payload).
- UDP join frame: `mode_id/map_id` = 1/1 (BR) vs 43/11 (LW) via `startup_params_for_mode()`.

## Files
Main.py (entry), master.py (bot), dashboard_server.py (dashboard + per-account state),
templates/index.html, *_pb2.py, message_ids.py, accounts.json, queue.json, devices.json, token_cache.json.
