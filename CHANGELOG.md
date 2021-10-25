# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [0.4.3] - 2021-10-25

### Fixed

- [`Plugoid`] Relaxed requirements for the `phoenix_html` dependency

## [0.4.2] - 2021-09-22

### Fixed

- [`Plugoid`] Fixed a bug with token hash validation in imported library

## [0.4.1] - 2020-10-16

### Fixed

- [`Plugoid`] Fixed erroneous handling of custom OP metadata

## [0.4.0] - 2020-09-26

### Added

- [`Plugoid.RedirectURI`] Mix-up attack protection. Redirect URIs are generated with an `iss`
parameter, which is verified when receiving the answer from the OP
