# Contributing

Thanks for taking a look at `terminal-tun`.

## Local setup

```bash
uv sync
uv run terminal-tun --help
```

## Tests

```bash
uv run python -m unittest discover -s tests -v
```

## Notes

- Keep runtime dependencies minimal.
- Prefer standard-library code where it stays readable.
- Validate generated `sing-box` config with:

```bash
uv run terminal-tun config check
```

- Do not commit local state files or generated `sing-box` configs.
