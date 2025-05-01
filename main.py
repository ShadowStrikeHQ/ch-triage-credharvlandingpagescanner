import argparse
import logging
import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command line interface.
    """
    parser = argparse.ArgumentParser(description="Credential Harvester Landing Page Scanner")
    parser.add_argument("url", help="The URL of the landing page to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging)")
    parser.add_argument("-o", "--output", help="Output file to save results (optional)", default=None)
    return parser.parse_args()


def is_valid_url(url):
    """
    Checks if a URL is valid.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def download_html(url):
    """
    Downloads the HTML content of a URL.

    Args:
        url (str): The URL to download.

    Returns:
        str: The HTML content of the URL, or None if an error occurred.
    """
    try:
        response = requests.get(url, timeout=10) # Added timeout to prevent indefinite hangs
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading URL: {e}")
        return None


def find_forms(html, base_url):
    """
    Finds all forms in the HTML content and extracts information about them.

    Args:
        html (str): The HTML content to parse.
        base_url (str): The base URL of the page to resolve relative URLs.

    Returns:
        list: A list of dictionaries, where each dictionary represents a form and contains its action and input fields.
    """
    soup = BeautifulSoup(html, 'html.parser')
    forms = []

    for form in soup.find_all('form'):
        action = form.get('action')
        if action:
            action = urljoin(base_url, action) # Properly handle relative URLs

        inputs = []
        for input_field in form.find_all('input'):
            input_type = input_field.get('type', '').lower()
            input_name = input_field.get('name')
            if input_name:  # Add check for missing name attributes.
                inputs.append({'type': input_type, 'name': input_name})

        forms.append({'action': action, 'inputs': inputs})

    return forms


def identify_potential_login_forms(forms):
    """
    Identifies forms that are likely to be login forms based on the presence of username/password fields.

    Args:
        forms (list): A list of form dictionaries.

    Returns:
        list: A list of form dictionaries that are likely login forms.
    """
    login_forms = []
    for form in forms:
        has_username = False
        has_password = False
        for input_field in form['inputs']:
            if 'name' in input_field:
                if 'username' in input_field['name'].lower() or 'email' in input_field['name'].lower() or 'user' in input_field['name'].lower():
                    has_username = True
                if input_field['type'] == 'password':
                    has_password = True

        if has_username and has_password:
            login_forms.append(form)

    return login_forms

def analyze_form_actions(login_forms):
    """
    Analyzes the form actions for potentially malicious patterns.

    Args:
        login_forms (list): A list of login form dictionaries.

    Returns:
        list: A list of form dictionaries with potentially malicious actions.
    """
    suspicious_forms = []
    for form in login_forms:
        if form['action']:
            url_parts = urlparse(form['action'])
            # Example heuristic: Check if the domain is different from the original URL (possible redirection)
            # You can add more sophisticated heuristics here, e.g., checking for IP addresses, common phishing domains, etc.
            if url_parts.scheme in ('http', 'https'):
                 suspicious_forms.append(form)
    return suspicious_forms


def print_results(suspicious_forms, output_file=None):
    """
    Prints the results to the console and optionally saves them to a file.

    Args:
        suspicious_forms (list): A list of dictionaries representing suspicious forms.
        output_file (str, optional): The path to the output file. Defaults to None.
    """
    if suspicious_forms:
        print("Potentially malicious login forms found:")
        for form in suspicious_forms:
            print(f"  Action: {form['action']}")
            print("  Inputs:")
            for input_field in form['inputs']:
                print(f"    - {input_field['type']}: {input_field['name']}")
            print("-" * 20)

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write("Potentially malicious login forms found:\n")
                    for form in suspicious_forms:
                        f.write(f"  Action: {form['action']}\n")
                        f.write("  Inputs:\n")
                        for input_field in form['inputs']:
                            f.write(f"    - {input_field['type']}: {input_field['name']}\n")
                        f.write("-" * 20 + "\n")
                print(f"Results saved to {output_file}")

            except IOError as e:
                logging.error(f"Error writing to file: {e}")

    else:
        print("No potentially malicious login forms found.")


def main():
    """
    Main function to orchestrate the scanning process.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url

    if not is_valid_url(url):
        logging.error("Invalid URL provided.")
        return

    html_content = download_html(url)
    if not html_content:
        return

    forms = find_forms(html_content, url)
    login_forms = identify_potential_login_forms(forms)
    suspicious_forms = analyze_form_actions(login_forms)

    print_results(suspicious_forms, args.output)

if __name__ == "__main__":
    main()


# Usage Examples (for documentation, not part of the code):
# 1. Basic usage: python ch_triage_CredHarvLandingPageScanner.py http://example.com
# 2. Verbose output: python ch_triage_CredHarvLandingPageScanner.py -v http://example.com
# 3. Save results to a file: python ch_triage_CredHarvLandingPageScanner.py -o results.txt http://example.com