# ch-triage-CredHarvLandingPageScanner
Given a URL, downloads the HTML content of the landing page and scans for input fields (username/password) and associated form submission endpoints.  Reports potentially malicious form actions. - Focused on Automates the initial triage of credential harvester output (e.g., logs from routers, web application credential stuffing attacks). Identifies likely valid credentials based on heuristics like password complexity, email validation, and common pattern analysis. Reduces the manual effort required to filter and validate captured credentials, focusing attention on the most promising leads.

## Install
`git clone https://github.com/ShadowStrikeHQ/ch-triage-credharvlandingpagescanner`

## Usage
`./ch-triage-credharvlandingpagescanner [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided
- `-o`: No description provided

## License
Copyright (c) ShadowStrikeHQ
