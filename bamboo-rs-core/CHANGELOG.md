# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-pre-29] - 2021-1-13
### Changed
- Move c bindings out into new module bamboo-c. Breaking change to name of libraries.
- Greatly improves Error types to include more information.

## [0.1.0-pre-28] - 2021-1-6
### Rename
- Renames everything from bamboo-\*  to bamboo-rs-\*. 

## [0.1.0-pre-27] - 2021-1-5
### Refactor
- Refactor out yamf-hash into seperate crate. No change to functionality. 

## [0.1.0-pre-26] - 2020-12-12
### Added
- Batch verify using rayon and simd now in bamboo-core when using std

## [0.1.0-pre-25] - 2020-10-29
### Changed
- Change how `author` is encoded in an entry. No longer uses YamfSignatory (this was removed from the spec.) Breaking change to `Entry` encoding.
- Test Vectors are updated.
- libbamboo.h headerfile is updated.

### Fixed
- Travis CI builds for PR's now all pass and broken builds are disabled.
