# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-pre-25] - 2020-10-29
### Changed
- Change how `author` is encoded in an entry. No longer uses YamfSignatory (this was removed from the spec.) Breaking change to `Entry` encoding.
- Change how the `$ bamboo-cli hash <file>` function encodes the result. It is now the canonical YamfHash encoding, not just the raw bytes of the hash.
- Testscript now fails fast.
- Testscript uses a "Hello World" textfile as the payload rather than the bamboo-cli executable.
