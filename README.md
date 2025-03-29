# ROADrecon MCP Server

This MCP (Model Context Protocol) server provides AI assistants like Claude with access to your ROADrecon Azure AD data for security analysis.

## Features

- **Resources**: Access Azure AD data from your ROADrecon instance
- **Tools**: Run security analysis on the data
- **Prompts**: Pre-built analysis templates for common security tasks

## Prerequisites

- Python 3.8+
- A running ROADrecon instance with the web GUI accessible
- MCP-compatible client (Claude Desktop, etc.)

## Installation

1. Clone this repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Running the server

1. Make sure your ROADrecon GUI is running (default: http://localhost:5000)

2. Run the MCP server:
   ```
   python roadrecon_mcp_server.py
   ```

3. To specify a different ROADrecon URL:
   ```
   ROADRECON_URL=http://localhost:8080 python roadrecon_mcp_server.py
   ```

### Connecting with Claude Desktop

1. Open Claude Desktop
2. Go to Settings → Servers → Add Server
3. Select "Add from running server" 
4. The server should appear in the list - click "Install"

### Using in Claude

Once connected, Claude can:
- Access Azure AD data via resources (e.g., `roadrecon://users`)
- Run security analysis with tools (e.g., `find_privileged_users`)
- Use pre-built prompts for common security tasks

## Example Queries

- "Analyze the MFA status of users in this Azure AD tenant"
- "Find all users with privileged roles"
- "Check for applications with secrets or certificates"
- "Analyze the overall security posture of this Azure AD environment"

## Resources Available

- `roadrecon://stats` - Summary statistics
- `roadrecon://users` - All users
- `roadrecon://users/{id}` - User details
- `roadrecon://groups` - All groups
- `roadrecon://groups/{id}` - Group details
- `roadrecon://applications` - All applications
- `roadrecon://applications/{id}` - Application details
- `roadrecon://serviceprincipals` - All service principals
- `roadrecon://serviceprincipals/{id}` - Service principal details
- `roadrecon://devices` - All devices
- `roadrecon://mfa` - MFA status for all users
- `roadrecon://directoryroles` - All directory roles
- `roadrecon://roledefinitions` - All role definitions
- `roadrecon://approles` - All app role assignments
- `roadrecon://oauth2permissions` - All OAuth2 permission grants
- `roadrecon://tenantdetails` - Tenant details

## Tools Available

- `find_privileged_users()` - Find users with high-privilege roles
- `analyze_mfa_status()` - Analyze MFA deployment across users
- `find_applications_with_secrets()` - Find applications with secrets/certificates
- `analyze_groups()` - Analyze group types and membership
- `identify_stale_accounts()` - Find accounts that haven't logged in or changed password within a specified period
- `analyze_pim_implementation()` - Assess Privileged Identity Management implementation
- `analyze_service_principal_credentials()` - Find over-permissioned service principals with long-lived credentials
- `analyze_legacy_authentication()` - Identify risks from legacy authentication protocols that bypass MFA
- `analyze_conditional_access_policies()` - Analyze conditional access implementations and security gaps

## Prompts Available

- `analyze_security_posture` - Comprehensive security analysis
- `analyze_privileged_access` - Analysis of privileged access model
- `investigate_application_risks` - Application security risk assessment
- `analyze_identity_security` - Identity security configuration analysis
- `analyze_stale_accounts` - Analysis of inactive user accounts
- `analyze_privileged_access_management` - PIM implementation assessment
- `analyze_service_principal_security` - Service principal credential risk analysis
- `analyze_legacy_authentication_risks` - Legacy authentication protocol risk assessment
- `analyze_conditional_access` - Analysis of conditional access policies and recommendations
- `comprehensive_security_review` - Complete security review of the entire environment

## License

MIT
