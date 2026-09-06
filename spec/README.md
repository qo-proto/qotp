# QOTP specification

`qotp-spec.typ` — the wire format and protocol rules, in the spirit of the
QOI specification: short enough to read in one sitting, complete enough to
implement from.

Build:

    typst compile qotp-spec.typ        # -> qotp-spec.pdf
    typst watch qotp-spec.typ          # live preview while editing

Install typst from https://github.com/typst/typst (or `pacman -S typst`,
`brew install typst`, `cargo install --locked typst-cli`).

The Readme covers rationale, tuning and implementation detail; this document
covers only what a second implementation would have to agree on.
