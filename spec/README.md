# QOTP specification

Two documents:

- `qotp-spec.typ` — the wire format and protocol rules, in the spirit of the
  QOI specification: short enough to read in one sitting, complete enough to
  implement from. Two pages.
- `qotp-why.typ` — the reasoning behind each mechanism of the reference
  implementation, numbered A.1 onwards; the spec refers to it as "Why, A.n".

Build:

    ./pdf.sh                           # -> qotp-spec.pdf, qotp-why.pdf
    typst watch qotp-spec.typ          # live preview while editing

Install typst from https://github.com/typst/typst (or `pacman -S typst`,
`brew install typst`, `cargo install --locked typst-cli`).

The spec is the normative part: what a second implementation would have to
agree on. The Why document is explanatory. The Readme covers usage and tuning.
