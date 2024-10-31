# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2024-10-30

### Added

- **Command-Line Argument Parsing:**
  - Implemented `argparse` for handling command-line arguments, providing a more user-friendly interface.
- **Environment Variable Support:**
  - Added the ability to provide the NordVPN API token via the `NORDVPN_TOKEN` environment variable, enhancing security by avoiding hardcoding tokens.
- **Flexible DNS Configuration:**
  - Enabled users to specify one or two DNS server IPs using the `--dns` flag.
  - Implemented automatic formatting of DNS inputs, handling cases without spaces after commas (e.g., `"1.1.1.1,1.0.0.1"` becomes `"1.1.1.1, 1.0.0.1"`).
- **Enhanced Logging:**
  - Replaced all `print` statements with Python's `logging` module for improved traceability and debugging.
  - Added logging for successful retrieval of the public key from the server.
  - Configured logging to include timestamps and severity levels.
- **Retry Mechanism:**
  - Implemented a retry mechanism with exponential backoff for network requests to handle transient failures gracefully.
- **Secure Configuration File Generation:**
  - Ensured the generated `wg0.conf` file has restrictive file permissions (`600`) to protect sensitive information.
- **User-Friendly Messages:**
  - Introduced a starting message to inform users that the configuration generation has begun.
  - Added a concluding success message upon successful generation of the WireGuard configuration.
- **Comprehensive Documentation:**
  - Updated `README.md` to accurately reflect all recent changes, noting that this repository is a fork of [Gui-greg/NordVPN-Wireguard-configurator](https://github.com/Gui-greg/NordVPN-Wireguard-configurator/).
  - Provided detailed usage instructions, including examples for different scenarios.
  - Added comprehensive instructions for obtaining the NordVPN API token.
  - Included sections for possible issues and troubleshooting to assist users in resolving common problems.
- **Improved Script Comments:**
  - Enhanced comments within the Python script to be more readable and provide basic details about each function and its purpose.

### Changed

- **DNS Server Handling:**
  - Enhanced DNS input validation to ensure correct formatting and valid IPv4 addresses.
- **Configuration Template:**
  - Updated the WireGuard configuration template to include `PersistentKeepalive = 25` in the `[Peer]` section.
- **Error Handling:**
  - Improved error messages to be more professional and user-friendly, especially when mandatory inputs are missing.
  - Provided clear instructions for obtaining the NordVPN API token if it is not specified.
- **Logging Configuration:**
  - Configured Python's `logging` module to display messages with timestamps and severity levels instead of using `print` statements.
- **README Documentation:**
  - Refined the README to include all recent changes and ensure clarity and professionalism in instructions and descriptions.

### Fixed

- **DNS Input Validation:**
  - Corrected potential issues with DNS input formatting by ensuring DNS servers are separated by a comma and a space.
- **File Permission Setting:**
  - Fixed issues related to setting secure file permissions on the generated `wg0.conf` file to ensure it is readable and writable only by the owner.
- **Public Key Retrieval:**
  - Added a log message confirming the successful retrieval of the public key from the server.

### Security

- **Secure Configuration File Generation:**
  - Set restrictive file permissions (`600`) on the generated `wg0.conf` file to protect sensitive information from unauthorized access.

### Documentation

- **Comprehensive README Updates:**
  - Included detailed instructions and security notes to guide users through the setup and usage of the tool.
  - Added sections for possible issues and troubleshooting to assist users in resolving common problems.

### Removed

- **Print Statements:**
  - Removed all `print` statements in favor of using the `logging` module for consistent and professional logging.

## [1.0.0] - 2024-08-28

Initial release based on [Gui-greg/NordVPN-Wireguard-configurator](https://github.com/Gui-greg/NordVPN-Wireguard-configurator/).

---
