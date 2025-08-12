# findcrypt-yara-x
IDA pro plugin to find crypto constants (and more) using YARA-X.

## Installation Notes
If [YARA-X](https://virustotal.github.io/yara-x/) is not already installed on your system, run `uv sync` to create a `.venv` which has YARA-X installed.

## User-defined rules

Custom rule files can be stored in :
 - `$HOME/.idapro/plugins/findcrypt-yara/*.yar` under Linux and MacOS.
 - `%APPDATA%\\Roaming\\Hex-Rays\\IDA Pro\\plugin\\findcrypt-yara\\*.yar` under Windows.
