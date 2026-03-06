# Backup & restore drill

Goal: make recovery predictable by practicing it.

## Drill steps
```bash
make up
make seed
make backup
make restore
```

## What “good” looks like
- You can restore without guessing commands.
- The backup artifact is versioned *out of band* (`artifacts/` is ignored).
- The process is documented and repeatable.

## Safety notes
- `make restore` restores into an **isolated** database (`appdb_verify`) and performs a small verification query.
- This keeps the drill repeatable without destroying your primary lab database.
