#!/usr/bin/env python3

import argparse
import os
import sys
import urllib.request
import json
import base64
import urllib.parse
import re
import logging
import time
from typing import Optional, Dict

# Configure logging to display messages with timestamps and severity levels
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Constants for NordVPN API endpoints and file paths
CREDENTIALS_URL = "https://api.nordvpn.com/v1/users/services/credentials"
RECOMMENDATIONS_BASE_URL = "https://api.nordvpn.com/v1/servers/recommendations"
GROUPS_URL = "https://api.nordvpn.com/v1/servers/groups"
COUNTRIES_URL = "https://api.nordvpn.com/v1/servers/countries"
CONFIG_TEMPLATE_PATH = "wireguard_config.template"
OUTPUT_CONFIG_PATH = "wg0.conf"

# Default DNS servers provided by NordVPN
DEFAULT_DNS = "103.86.96.100, 103.86.99.100"

# Configuration for retrying network requests
MAX_RETRIES = 3    # Maximum number of retry attempts
RETRY_DELAY = 5    # Delay between retries in seconds

def terminate_program(msg: str):
    """
    Logs an error message, informs the user that the program is terminating,
    and exits the script.
    
    Parameters:
        msg (str): The error message to display.
    """
    logger.error(msg)
    logger.info("Program is terminating!")
    sys.exit(1)

def fetch_data_with_retries(url: str, headers: Optional[Dict[str, str]] = None, retries: int = MAX_RETRIES, delay: int = RETRY_DELAY) -> Dict:
    """
    Fetches data from a specified URL with retry logic to handle transient errors.
    
    Parameters:
        url (str): The URL to fetch data from.
        headers (Optional[Dict[str, str]]): HTTP headers to include in the request.
        retries (int): Number of retry attempts.
        delay (int): Delay between retries in seconds.
    
    Returns:
        Dict: The JSON-decoded response data.
    
    Raises:
        Terminates the program if all retry attempts fail.
    """
    for attempt in range(1, retries + 1):
        try:
            request = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(request) as response:
                if response.status != 200:
                    raise urllib.error.HTTPError(url, response.status, response.reason, response.headers, None)
                data = response.read()
                return json.loads(data.decode())
        except urllib.error.HTTPError as e:
            logger.warning(f"HTTPError on attempt {attempt} for URL '{url}': {e.code} {e.reason}")
        except urllib.error.URLError as e:
            logger.warning(f"URLError on attempt {attempt} for URL '{url}': {e.reason}")
        except json.JSONDecodeError:
            logger.warning(f"JSONDecodeError on attempt {attempt} for URL '{url}'.")
        except Exception as e:
            logger.warning(f"Unexpected error on attempt {attempt} for URL '{url}': {e}")
        
        if attempt < retries:
            logger.info(f"Retrying in {delay} seconds...")
            time.sleep(delay)
        else:
            terminate_program(f"Failed to fetch data from '{url}' after {retries} attempts.")

def get_country_id(country_input: str) -> int:
    """
    Retrieves the country ID based on user input (code, name, or ID).
    
    Parameters:
        country_input (str): The user-provided country identifier.
    
    Returns:
        int: The corresponding country ID.
    
    Raises:
        Terminates the program if the country is not found.
    """
    countries = fetch_data_with_retries(COUNTRIES_URL)
    for country in countries:
        if (str(country["id"]) == country_input or
            country["code"].lower() == country_input.lower() or
            country["name"].lower() == country_input.lower()):
            logger.info(f"Country '{country_input}' matched with ID {country['id']}.")
            return country["id"]
    terminate_program(f"Country '{country_input}' not found. Please provide a valid country code, name, or ID.")

def get_group_identifier(group_input: str) -> str:
    """
    Retrieves the group identifier based on user input (title or identifier).
    
    Parameters:
        group_input (str): The user-provided group identifier.
    
    Returns:
        str: The corresponding group identifier.
    
    Raises:
        Terminates the program if the group is not found.
    """
    groups = fetch_data_with_retries(GROUPS_URL)
    for group in groups:
        if (group["identifier"].lower() == group_input.lower() or
            group["title"].lower() == group_input.lower()):
            logger.info(f"Group '{group_input}' matched with identifier '{group['identifier']}'.")
            return group["identifier"]
    terminate_program(f"Group '{group_input}' not found. Please provide a valid group title or identifier.")

def validate_dns(dns_input: str, dns_specified: bool) -> str:
    """
    Validates and formats DNS server IPs provided by the user.
    
    Parameters:
        dns_input (str): The user-provided DNS servers as a string.
        dns_specified (bool): Indicates whether DNS was specified by the user.
    
    Returns:
        str: A formatted string of DNS servers separated by a comma and space.
    
    Raises:
        Terminates the program if DNS servers are invalid or incorrectly formatted.
    """
    if not dns_specified:
        # User did not specify DNS; use default DNS servers
        logger.info("No DNS servers specified.")
        logger.info(f"Using Default NordVPN DNS servers: {DEFAULT_DNS}")
        return DEFAULT_DNS

    # Split the DNS input by commas and remove any surrounding whitespace
    dns_servers = [dns.strip() for dns in dns_input.split(',')]
    
    # Ensure that only 1 or 2 DNS servers are provided
    if not (1 <= len(dns_servers) <= 2):
        terminate_program("Please provide between 1 to 2 DNS server IPs separated by a comma.")
    
    # Regular expression to validate IPv4 addresses
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    for dns in dns_servers:
        if not ip_pattern.match(dns):
            terminate_program(f"Invalid DNS IP address format: '{dns}'.")
        # Further validate that each octet is between 0 and 255
        octets = dns.split('.')
        for octet in octets:
            if not 0 <= int(octet) <= 255:
                terminate_program(f"Invalid DNS IP address value: '{dns}'. Each octet must be between 0 and 255.")
    
    # Join the DNS servers with a comma and space
    formatted_dns = ', '.join(dns_servers)
    logger.info(f"Using DNS servers: {formatted_dns}")
    return formatted_dns

def get_server_details(api_token: str, country: Optional[str], group: Optional[str]) -> Dict:
    """
    Fetches and returns server details based on the provided country and group filters.
    
    Parameters:
        api_token (str): The NordVPN API token for authentication.
        country (Optional[str]): The country filter (code, name, or ID).
        group (Optional[str]): The group filter (title or identifier).
    
    Returns:
        Dict: A dictionary containing server name, hostname, and public key.
    
    Raises:
        Terminates the program if server details cannot be retrieved.
    """
    # Encode the API token for HTTP Basic Authentication
    encoded_token = base64.b64encode(f"token:{api_token}".encode()).decode()
    auth_headers = {"Authorization": f"Basic {encoded_token}"}

    # Initialize filters for the API request
    filters = {
        "servers_technologies.identifier": "wireguard_udp"
    }

    # Add group filter if specified
    if group:
        group_identifier = get_group_identifier(group)
        filters["servers_groups.identifier"] = group_identifier

    # Add country filter if specified
    if country:
        country_id = get_country_id(country)
        filters["country_id"] = str(country_id)

    # Construct query parameters with proper encoding for nested filters
    query_params = []
    for key, value in filters.items():
        if '.' in key:
            # Replace '.' with '[' and ']' for nested filters (e.g., filters[servers_technologies][identifier]=wireguard_udp)
            parts = key.split('.')
            key_formatted = f"filters[{parts[0]}][{parts[1]}]"
        else:
            key_formatted = key
        query_params.append(f"{urllib.parse.quote(key_formatted)}={urllib.parse.quote(value)}")

    # Combine query parameters into a single query string
    query_string = "&".join(query_params)
    recommendations_url = f"{RECOMMENDATIONS_BASE_URL}?{query_string}&limit=1"
    logger.debug(f"Recommendations URL: {recommendations_url}")

    # Fetch recommended server details
    recommended_server_response = fetch_data_with_retries(recommendations_url)
    if not recommended_server_response or not recommended_server_response[0].get("name"):
        terminate_program(f"Recommended server failed to retrieve. Response: {recommended_server_response}")

    # Extract server information from the response
    server = recommended_server_response[0]
    server_name = server["name"]
    server_hostname = server.get("hostname") or server.get("station")  # Fallback to 'station' if 'hostname' not available

    if not server_hostname:
        terminate_program("Server hostname not found in the server data.")

    # Extract WireGuard technology details
    wireguard_technology = next((tech for tech in server.get("technologies", []) if tech["identifier"] == "wireguard_udp"), None)
    if not wireguard_technology:
        terminate_program("WireGuard UDP not supported by the server.")

    # Extract the public key from the WireGuard technology metadata
    public_key = next((item["value"] for item in wireguard_technology.get("metadata", []) if item["name"] == "public_key"), None)
    if not public_key:
        terminate_program("Public key not found in WireGuard UDP technology.")
    
    # Log successful retrieval of the public key
    logger.info("Successfully retrieved the public key from the server.")

    logger.info(f"Selected server: {server_name} ({server_hostname})")
    return {
        "server_name": server_name,
        "server_hostname": server_hostname,
        "public_key": public_key
    }

def fetch_credentials(api_token: str) -> str:
    """
    Fetches NordVPN credentials and returns the private key required for WireGuard configuration.
    
    Parameters:
        api_token (str): The NordVPN API token for authentication.
    
    Returns:
        str: The NordVPN private key.
    
    Raises:
        Terminates the program if credentials cannot be retrieved.
    """
    # Encode the API token for HTTP Basic Authentication
    encoded_token = base64.b64encode(f"token:{api_token}".encode()).decode()
    auth_headers = {"Authorization": f"Basic {encoded_token}"}

    # Fetch credentials from NordVPN API
    credentials_response = fetch_data_with_retries(CREDENTIALS_URL, headers=auth_headers)
    private_key = credentials_response.get("nordlynx_private_key")
    if not private_key:
        terminate_program(f"Credentials failed to retrieve. Response: {credentials_response}")
    logger.info("Successfully retrieved the private key from NordVPN.")
    return private_key

def read_template(template_path: str) -> str:
    """
    Reads and returns the WireGuard configuration template from a file.
    
    Parameters:
        template_path (str): The path to the WireGuard configuration template file.
    
    Returns:
        str: The content of the configuration template.
    
    Raises:
        Terminates the program if the template file cannot be read.
    """
    try:
        with open(template_path, "r") as file:
            config_template = file.read()
            logger.debug(f"Read configuration template from '{template_path}'.")
            return config_template
    except FileNotFoundError:
        terminate_program(f"Config template file '{template_path}' not found.")
    except IOError as e:
        terminate_program(f"Failed to read config template file: {e}")

def write_config(output_path: str, config: str):
    """
    Writes the WireGuard configuration to the specified output file and sets secure file permissions.
    
    Parameters:
        output_path (str): The path to the output WireGuard configuration file.
        config (str): The WireGuard configuration content to write.
    
    Raises:
        Terminates the program if the configuration file cannot be written or permissions cannot be set.
    """
    try:
        with open(output_path, "w") as file:
            file.write(config)
        logger.info(f"Configuration written to '{output_path}'.")
        
        # Set file permissions to read/write for the user only (600)
        os.chmod(output_path, 0o600)
        logger.info(f"Set file permissions for '{output_path}' to 600.")
    except IOError as e:
        terminate_program(f"Failed to write config file: {e}")
    except Exception as e:
        terminate_program(f"Failed to set file permissions: {e}")

def main():
    """
    The main function orchestrates the generation of the WireGuard configuration.
    It parses command-line arguments, validates inputs, fetches necessary data from NordVPN's API,
    and writes the final configuration file.
    """
    # Display a starting message
    logger.info("Starting WireGuard configuration generation...")

    # Set up argument parsing using argparse for a user-friendly command-line interface
    parser = argparse.ArgumentParser(
        description="Generate a WireGuard configuration using NordVPN's API."
    )
    parser.add_argument(
        '--token',
        dest='NORDVPN_TOKEN',
        type=str,
        help='Your NordVPN API token. Alternatively, set the NORDVPN_TOKEN environment variable.',
    )
    parser.add_argument(
        '--country',
        type=str,
        help='Country code (e.g., CA), name (e.g., Canada), or ID (e.g., 38).'
    )
    parser.add_argument(
        '--group',
        type=str,
        help='Server group title (e.g., P2P) or identifier (e.g., legacy_p2p).'
    )
    parser.add_argument(
        '--dns',
        type=str,
        help='Comma-separated DNS server IPs (1-2). Example: "1.1.1.1, 1.0.0.1".',
        default=None
    )

    # Parse the provided command-line arguments
    args = parser.parse_args()

    # Retrieve API token from arguments or environment variable
    api_token = args.NORDVPN_TOKEN or os.getenv("NORDVPN_TOKEN")
    if not api_token:
        # Professional and clear instructions for obtaining an API token
        token_instructions = (
            "No token specified. To obtain a token, please follow these steps:\n\n"
            "1. Go to: https://my.nordaccount.com/dashboard/nordvpn/access-tokens/\n"
            "2. Click on the 'Get Access Token' button.\n"
            "3. Click the 'Generate New Token' button.\n"
            "4. Choose 'Doesn't expire' and click 'Generate Token'.\n"
            "5. Click 'Copy and Close'. This action will save the token to your clipboard.\n"
        )
        terminate_program(token_instructions)

    # Extract other arguments
    country_input = args.country
    group_input = args.group
    dns_input = args.dns

    # Determine if DNS was specified by the user
    dns_specified = dns_input is not None

    # Validate and format DNS servers
    if dns_specified:
        # Handle cases where the user might not include a space after the comma
        # e.g., "1.1.1.1,1.0.0.1" becomes "1.1.1.1, 1.0.0.1"
        dns_input = re.sub(r',\s*', ', ', dns_input)
        dns_servers = validate_dns(dns_input, dns_specified=True)
    else:
        dns_servers = validate_dns(dns_input, dns_specified=False)

    # Fetch NordVPN credentials (private key)
    private_key = fetch_credentials(api_token)

    # Fetch server details based on country and group filters
    server_details = get_server_details(api_token, country_input, group_input)

    # Read the WireGuard configuration template
    config_template = read_template(CONFIG_TEMPLATE_PATH)

    # Format the configuration with the retrieved values
    config = config_template.format(
        server_name=server_details["server_name"],
        private_key=private_key,
        public_key=server_details["public_key"],
        server_hostname=server_details["server_hostname"],
        dns_servers=dns_servers
    )

    # Write the formatted configuration to the output file
    write_config(OUTPUT_CONFIG_PATH, config)

    # Display a concluding success message
    logger.info(f"Successfully created a WireGuard config for server: {server_details['server_name']}")
    logger.info("WireGuard configuration generation completed successfully.")

# Ensure the script runs the main function when executed directly
if __name__ == "__main__":
    main()
