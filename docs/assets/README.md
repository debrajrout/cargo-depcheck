# Demo assets

Generated from the tool's real output, not hand-drawn:

```sh
CLICOLOR_FORCE=1 COLUMNS=84 cargo depcheck --top 3 > report.ansi
CLICOLOR_FORCE=1 COLUMNS=84 cargo depcheck explain wasi --max-paths 3 > explain.ansi

python3 tools/render-demo.py docs/assets/demo-report.svg \
  --title "cargo depcheck --top 3" --input report.ansi \
  --strip 'Fetching|^cargo-depcheck v|Analyzing'

python3 tools/render-demo.py docs/assets/demo-explain.svg \
  --title "cargo depcheck explain wasi" --input explain.ansi \
  --strip 'Fetching|^cargo-depcheck v|Analyzing|advisory database ready|^Found '
```

`--strip` drops the progress lines, which the tool overwrites in place with a
carriage return — a real terminal never shows a spinner next to the result it
was waiting for, so a still image that kept both would be less accurate, not
more.
