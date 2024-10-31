
# WireGuard Configuration Generator for NordVPN (Fork)

**Forked from [Gui-greg/NordVPN-Wireguard-configurator](https://github.com/Gui-greg/NordVPN-Wireguard-configurator/)**

## Overview

NordVPN does not currently provide an official method to generate WireGuard configuration files. This tool simplifies the process of creating a WireGuard configuration (`wg0.conf`) tailored for your NordVPN subscription. It leverages NordVPN's API to retrieve necessary credentials and server information, ensuring a secure and efficient setup for various applications.

## Features

- **User-Friendly Command-Line Interface:** Utilize intuitive flags for specifying parameters such as country, server group, and DNS servers.
- **Environment Variable Support:** Securely provide your NordVPN API token via environment variables.
- **Flexible DNS Configuration:** Specify one or two DNS servers with automatic formatting.
- **Robust Error Handling:** Clear and professional messages guide you through any issues encountered.
- **Logging:** Detailed logs provide insights into the script's execution flow.
- **Secure Configuration File:** The generated `wg0.conf` file is secured with appropriate file permissions to protect sensitive information.

## Prerequisites

Before using this tool, ensure you have the following:

- **Python 3:** Installed on your system. You can verify installation by running `python3 --version` in your terminal.
- **WireGuard:** Installed if you intend to use the generated configuration. Installation instructions can be found on the [WireGuard website](https://www.wireguard.com/install/).
- **Active NordVPN Subscription:** Required to access NordVPN's services and generate necessary credentials.
- **Internet Connection:** To communicate with NordVPN's API and retrieve server information.

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/YourUsername/NordVPN-Wireguard-configurator.git
   cd NordVPN-Wireguard-configurator
   ```

2. **Ensure Dependencies are Met:**

   This script utilizes only Python's standard libraries, so no additional installations are required.

3. **Set Up the Configuration Template:**

   Ensure the `wireguard_config.template` file is present in the repository with the following content:

   ```ini
   # Config for NordVPN server {server_name}
   [Interface]
   Address = 10.5.0.2/32
   PrivateKey = {private_key}
   DNS = {dns_servers}

   [Peer]
   PublicKey = {public_key}
   Endpoint = {server_hostname}:51820
   AllowedIPs = 0.0.0.0/0
   PersistentKeepalive = 25
   ```

## Obtaining a NordVPN API Token

To generate a WireGuard configuration, you need an API token from NordVPN. Follow these steps to obtain one:

1. **Navigate to NordVPN's Access Tokens Page:**

   Go to [NordVPN Access Tokens](https://my.nordaccount.com/dashboard/nordvpn/access-tokens/).

2. **Generate a New Token:**
   - Click on the "Get Access Token" button.
   - Click the "Generate New Token" button.
   - Choose "Doesn't expire" to create a non-expiring token.
   - Click "Generate Token".
   - Click "Copy and Close" to save the token to your clipboard.

   **Security Note:** Treat your API token with the same confidentiality as your password. Do not share it or expose it in unsecured environments.

## Usage

You can run the script using either command-line arguments or environment variables for enhanced security.

### 1. Using Command-Line Arguments

Run the script with the necessary flags:

```bash
python3 generate_config.py --token "YOUR_API_TOKEN" [--country "Country"] [--group "Group"] [--dns "DNS1,DNS2"]
```

**Parameters:**

- `--token`: (Required) Your NordVPN API token.
- `--country`: (Optional) Specify the country by code (e.g., CA), name (e.g., Canada), or ID (e.g., 38).
- `--group`: (Optional) Specify the server group by title (e.g., P2P) or identifier (e.g., legacy_p2p).
- `--dns`: (Optional) Specify one or two DNS server IPs separated by a comma (e.g., "1.1.1.1,1.0.0.1"). The script will format it as "1.1.1.1, 1.0.0.1".

**Example:**

```bash
python3 generate_config.py --token "e8gftmhqdqlysrsz7m8mbnqhd6ckgyn3pgpfgtecbtgrvj6ubxp3vjq88ljmntjbs" --country "Canada" --group "P2P" --dns "1.1.1.1,1.0.0.1"
```

### 2. Using Environment Variables

For enhanced security, you can provide the API token via an environment variable:

1. **Set the Environment Variable:**

   ```bash
   export NORDVPN_TOKEN="YOUR_API_TOKEN"
   ```

2. **Run the Script Without the `--token` Flag:**

   ```bash
   python3 generate_config.py [--country "Country"] [--group "Group"] [--dns "DNS1,DNS2"]
   ```

**Example:**

```bash
python3 generate_config.py --country "Canada" --group "P2P" --dns "1.1.1.1,1.0.0.1"
```

### 3. Running Without Optional Arguments

If you omit optional arguments, the script will use default settings:

- **Country:** Randomly selected based on your NordVPN subscription.
- **Group:** Default group if not specified.
- **DNS:** Defaults to NordVPN's DNS servers (103.86.96.100, 103.86.99.100).

**Example:**

```bash
python3 generate_config.py --token "YOUR_API_TOKEN"
```

## Output

Upon successful execution, the script will generate a `wg0.conf` file in the current directory with the necessary WireGuard configuration. The file includes:

- **Interface Section:**
  - `Address`: Assigned IP address.
  - `PrivateKey`: Your NordLynx private key.
  - `DNS`: Specified or default DNS servers.

- **Peer Section:**
  - `PublicKey`: Server's public key.
  - `Endpoint`: Server's hostname and port.
  - `AllowedIPs`: Traffic routing configuration.
  - `PersistentKeepalive`: Maintains the connection.

**Sample Output Message:**

```vbnet
INFO: Starting WireGuard configuration generation...
INFO: Successfully retrieved the private key from NordVPN.
INFO: Successfully retrieved the public key from the server.
INFO: Selected server: Canada #1582 (ca1582.nordvpn.com)
INFO: Configuration written to 'wg0.conf'.
INFO: Set file permissions for 'wg0.conf' to 600.
INFO: Successfully created a WireGuard config for server: Canada #1582
INFO: WireGuard configuration generation completed successfully.
```

## Securing the Configuration File

The generated `wg0.conf` file contains sensitive information. Ensure it has restrictive permissions to prevent unauthorized access:

```bash
chmod 600 wg0.conf
```

## Possible Issues and Troubleshooting

### 1. Python Not Found

**Error Message:**

```yaml
env: python3: No such file or directory
```

**Possible Cause:** Python 3 is not installed or not available in your system's PATH.

**Solution:**

- **Verify Python Installation:**

  ```bash
  python3 --version
  ```

- **Run the Script with Explicit Python Command:**

  If `python3` is not recognized, try:

  ```bash
  python generate_config.py --token "YOUR_API_TOKEN"
  ```

- **Install Python 3:**

  Follow the installation instructions for your operating system from the [official Python website](https://www.python.org/downloads/).

### 2. Invalid DNS Server Format

**Error Message:**

```css
Invalid DNS IP address format: '1.1.1.1,1.0.0.1'.
```

**Possible Cause:** DNS servers are not correctly formatted or contain invalid IP addresses.

**Solution:**

- **Ensure Proper Formatting:**

  Use a comma followed by a space to separate DNS servers:

  ```bash
  --dns "1.1.1.1, 1.0.0.1"
  ```

- **Provide Valid IPv4 Addresses:**

  Confirm that the DNS IPs are correctly formatted and valid.

### 3. Missing or Incorrect API Token

**Error Message:**

```css
No token specified. To obtain a token, please follow these steps:
...
```

**Possible Cause:** API token not provided or incorrectly set.

**Solution:**

- **Provide the API Token:**

  Via command-line argument:

  ```bash
  --token "YOUR_API_TOKEN"
  ```

  Or set the environment variable:

  ```bash
  export NORDVPN_TOKEN="YOUR_API_TOKEN"
  ```

- **Ensure Token Validity:** Confirm that the token is correctly generated and copied.

### 4. Unable to Retrieve Credentials or Server Details

**Error Message:**

```sql
Failed to fetch data from 'https://api.nordvpn.com/v1/users/services/credentials' after 3 attempts.
```

**Possible Cause:** Network issues, invalid API token, or NordVPN API downtime.

**Solution:**

- **Check Internet Connection:** Ensure your device is connected to the internet.
- **Verify API Token:** Confirm that your API token is correct and has not been revoked.
- **Retry Later:** If NordVPN's API is experiencing downtime, wait and try again later.

## Contributing

This project is a fork of Gui-greg/NordVPN-Wireguard-configurator. Contributions, improvements, and suggestions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License.

## Disclaimer

Use this tool at your own risk. Ensure that you comply with NordVPN's terms of service and policies when using their API and services.
