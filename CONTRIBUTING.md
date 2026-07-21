# Contributing

Contributions are welcome for deterministic GitHub Actions workflow checks with low false-positive risk.

1. Open an issue describing the unsafe pattern, safe counterexample, and authoritative security rationale.
2. Add one failing test first.
3. Run that test and confirm it fails for the intended reason.
4. Add the smallest implementation that passes.
5. Run the complete suite:

```bash
python -m unittest discover -s tests -v
```

Do not submit rules that require repository secrets, transmit workflow contents, execute untrusted workflow code, or depend on a paid API.
