# Instructions for coding agents

The syslog protocol with structured data, the transport mappings that matter (UDP, TCP framing, TLS, DTLS) and a receiver that does not lose a line.

Primary documents are listed in `docs/rfc-map.md` with statuses and known errata.
The obligation table in `ROADMAP.md` is the work queue, and `README.md` explains
what the library is for. Read those three before changing anything.

## Commands

    python -m pip install -e ".[dev]"
    python -m pytest -q
    python -m pytest -q tests/test_roadmap_rows.py
    python -m pytest -q tests/test_public_api.py::test_stubs_are_loud
    python -m ruff check .
    python -m ruff format --check .
    python -m mypy syslogkit

The first line installs the dev extras. The six commands after it are the gates,
and all six must pass before a change is finished. CI runs the same set on Linux
and Windows, plus the suite under `python -O`.

## Invariants

These are the points where a plausible-looking change makes the project wrong
rather than merely incomplete.

1. **Roadmap honesty.** Never change a `ROADMAP.md` row from `[ ]` to `[x]` unless
   the test named in its `Evidence` cell exists and passes. `tests/test_roadmap_rows.py`
   fails on any row that claims done without a named test, and that check is the
   reason the roadmap can be trusted. Do not weaken it, skip it, or delete it to
   get a green run.
2. **No silent stubs.** Code that is not implemented raises `NotImplementedError`.
   Never return an empty value, an empty collection, or a result object that reports
   success. A protocol library that answers nothing is worse than one that refuses
   to answer, and `tests/test_public_api.py` enforces that every stub is loud.
3. **Normative text is never paraphrased from memory.** Fetch it with `rfclib` and
   cite the section. If the text you fetch does not say what the obligation claims,
   the obligation is wrong: fix the roadmap row and say so in the commit.
4. **Dependencies.** `pyproject.toml` here declares no runtime dependencies. Adding a runtime
   dependency needs a paragraph of justification in `docs/strategy.md` explaining
   why the standard library is not enough.
5. **Scope.** What is deliberately absent is listed under Non-goals in `README.md`.
   An agent that "helpfully" implements a non-goal has expanded the API surface that
   has to be supported forever.

## Read before implementing

- RFC 5424 has 5 errata on file with none verified; RFC 5425 has 2 on file, none verified. Re-check both pages before M1.
- RFC 6587 is Historic, not Standards Track: it describes deployed practice, so framing tests must include the implementations it documents.
- RFC 5424 obsoleted RFC 3164. A 3164 parser is a compatibility layer, and says so in its name.

## Protocol work

`.clinerules/10-rfclib.md` describes the `rfclib` calls to make for each obligation
and lists the section refs for this project. If you are not running in Cline, the
same procedure applies: confirm the document, read its errata, pull the normative
statements, then write code.
