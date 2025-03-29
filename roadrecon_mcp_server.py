#!/usr/bin/env python3
"""
ROADrecon MCP Server
Provides MCP access to ROADrecon Azure AD data for analysis by LLMs
"""

import json
import httpx
from typing import List, Dict, Any, Optional
import os
from datetime import datetime, timedelta
from mcp.server.fastmcp import FastMCP, Context, Image

# Create an MCP server
mcp = FastMCP("ROADrecon Analyzer")

# Configuration for ROADrecon API
ROADRECON_BASE_URL = os.environ.get("ROADRECON_URL", "http://localhost:5000")

# Helper function to call the ROADrecon API
async def call_roadrecon_api(endpoint: str) -> Any:
    """Make a request to the ROADrecon API"""
    url = f"{ROADRECON_BASE_URL}/api/{endpoint}"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
    except Exception as e:
        return {"error": str(e)}

# Resources
@mcp.resource("roadrecon://stats")
async def get_stats() -> str:
    """Get summary statistics about the Azure AD tenant"""
    data = await call_roadrecon_api("stats")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://users")
async def get_users() -> str:
    """Get all users in the Azure AD tenant"""
    data = await call_roadrecon_api("users")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://users/{user_id}")
async def get_user_detail(user_id: str) -> str:
    """Get detailed information about a specific user"""
    data = await call_roadrecon_api(f"users/{user_id}")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://groups")
async def get_groups() -> str:
    """Get all groups in the Azure AD tenant"""
    data = await call_roadrecon_api("groups")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://groups/{group_id}")
async def get_group_detail(group_id: str) -> str:
    """Get detailed information about a specific group"""
    data = await call_roadrecon_api(f"groups/{group_id}")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://applications")
async def get_applications() -> str:
    """Get all applications in the Azure AD tenant"""
    data = await call_roadrecon_api("applications")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://applications/{app_id}")
async def get_application_detail(app_id: str) -> str:
    """Get detailed information about a specific application"""
    data = await call_roadrecon_api(f"applications/{app_id}")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://serviceprincipals")
async def get_service_principals() -> str:
    """Get all service principals in the Azure AD tenant"""
    data = await call_roadrecon_api("serviceprincipals")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://serviceprincipals/{sp_id}")
async def get_service_principal_detail(sp_id: str) -> str:
    """Get detailed information about a specific service principal"""
    data = await call_roadrecon_api(f"serviceprincipals/{sp_id}")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://devices")
async def get_devices() -> str:
    """Get all devices in the Azure AD tenant"""
    data = await call_roadrecon_api("devices")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://mfa")
async def get_mfa_details() -> str:
    """Get MFA status for all users"""
    data = await call_roadrecon_api("mfa")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://directoryroles")
async def get_directory_roles() -> str:
    """Get all directory roles in the Azure AD tenant"""
    data = await call_roadrecon_api("directoryroles")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://roledefinitions")
async def get_role_definitions() -> str:
    """Get all role definitions in the Azure AD tenant"""
    data = await call_roadrecon_api("roledefinitions")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://approles")
async def get_app_roles() -> str:
    """Get all app role assignments"""
    data = await call_roadrecon_api("approles")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://oauth2permissions")
async def get_oauth_permissions() -> str:
    """Get all OAuth2 permission grants"""
    data = await call_roadrecon_api("oauth2permissions")
    return json.dumps(data, indent=2)

@mcp.resource("roadrecon://tenantdetails")
async def get_tenant_details() -> str:
    """Get tenant details"""
    data = await call_roadrecon_api("tenantdetails")
    return json.dumps(data, indent=2)

# Tools for analysis
@mcp.tool()
async def find_privileged_users() -> Dict[str, Any]:
    """Find users with high-privilege directory roles"""
    roles = await call_roadrecon_api("directoryroles")
    privileged_roles = [
        "Global Administrator", 
        "Privileged Role Administrator",
        "Conditional Access Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Security Administrator"
    ]
    
    privileged_users = {}
    for role in roles:
        if role.get("displayName") in privileged_roles and role.get("memberUsers"):
            for user in role.get("memberUsers", []):
                user_id = user.get("objectId")
                if user_id not in privileged_users:
                    privileged_users[user_id] = {
                        "displayName": user.get("displayName"),
                        "userPrincipalName": user.get("userPrincipalName"),
                        "roles": []
                    }
                privileged_users[user_id]["roles"].append(role.get("displayName"))
    
    return {
        "privilegedUsers": list(privileged_users.values()),
        "totalCount": len(privileged_users)
    }

@mcp.tool()
async def analyze_mfa_status() -> Dict[str, Any]:
    """Analyze MFA status across all users"""
    users_mfa = await call_roadrecon_api("mfa")
    total_users = len(users_mfa)
    
    analysis = {
        "totalUsers": total_users,
        "usersWithMFA": 0,
        "usersWithoutMFA": 0,
        "disabledUsers": 0,
        "mfaMethods": {
            "app": 0,
            "phone": 0,
            "fido": 0
        },
        "atRiskUsers": []
    }
    
    for user in users_mfa:
        if not user.get("accountEnabled", True):
            analysis["disabledUsers"] += 1
            continue
            
        if user.get("mfamethods", 0) > 0:
            analysis["usersWithMFA"] += 1
            
            if user.get("has_app"):
                analysis["mfaMethods"]["app"] += 1
            if user.get("has_phonenr"):
                analysis["mfaMethods"]["phone"] += 1
            if user.get("has_fido"):
                analysis["mfaMethods"]["fido"] += 1
        else:
            analysis["usersWithoutMFA"] += 1
            analysis["atRiskUsers"].append({
                "displayName": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
                "objectId": user.get("objectId")
            })
    
    return analysis

@mcp.tool()
async def find_applications_with_secrets() -> Dict[str, Any]:
    """Find applications with secrets or certificates and analyze their expiration"""
    applications = await call_roadrecon_api("applications")
    apps_with_secrets = []
    
    for app in applications:
        password_creds = app.get("passwordCredentials", [])
        key_creds = app.get("keyCredentials", [])
        
        if password_creds or key_creds:
            app_data = {
                "displayName": app.get("displayName"),
                "objectId": app.get("objectId"),
                "appId": app.get("appId"),
                "passwordCredentials": len(password_creds),
                "keyCredentials": len(key_creds),
                "availableToOtherTenants": app.get("availableToOtherTenants", False)
            }
            apps_with_secrets.append(app_data)
    
    return {
        "applicationsWithSecrets": apps_with_secrets,
        "totalCount": len(apps_with_secrets)
    }

@mcp.tool()
async def analyze_groups() -> Dict[str, Any]:
    """Analyze group types and membership in the tenant"""
    groups = await call_roadrecon_api("groups")
    
    analysis = {
        "totalGroups": len(groups),
        "groupsByType": {
            "security": 0,
            "mail": 0,
            "dynamic": 0,
            "assigned": 0,
            "dirSync": 0
        },
        "assignableToRole": 0,
        "nestedGroups": 0
    }
    
    for group in groups:
        is_security = not group.get("isPublic", False)
        has_mail = bool(group.get("mail"))
        is_dynamic = bool(group.get("membershipRule"))
        is_dir_synced = group.get("dirSyncEnabled", False)
        
        if is_security:
            analysis["groupsByType"]["security"] += 1
        if has_mail:
            analysis["groupsByType"]["mail"] += 1
        if is_dynamic:
            analysis["groupsByType"]["dynamic"] += 1
        else:
            analysis["groupsByType"]["assigned"] += 1
        if is_dir_synced:
            analysis["groupsByType"]["dirSync"] += 1
            
        if group.get("isAssignableToRole", False):
            analysis["assignableToRole"] += 1
    
    return analysis

@mcp.tool()
async def identify_stale_accounts(days: int = 90) -> Dict[str, Any]:
    """Find user accounts that have not logged in or changed password in a specified number of days"""
    users = await call_roadrecon_api("users")
    
    today = datetime.now()
    cutoff_date = today - timedelta(days=days)
    stale_login_accounts = []
    stale_password_accounts = []
    enabled_stale_accounts = []
    total_users = 0
    
    for user in users:
        # Skip account if it's not a user account (e.g., service account)
        if user.get("userType") == "Guest" or not user.get("userPrincipalName"):
            continue
            
        total_users += 1
        account_is_stale = False
        last_login = None
        last_password_change = None
        
        # Look for last sign-in time in various possible fields
        if user.get("lastDirSyncTime"):
            try:
                last_login = datetime.fromisoformat(user.get("lastDirSyncTime").replace('Z', '+00:00'))
            except (ValueError, TypeError):
                pass
        
        # Get last password change date
        if user.get("lastPasswordChangeDateTime"):
            try:
                last_password_change = datetime.fromisoformat(user.get("lastPasswordChangeDateTime").replace('Z', '+00:00'))
            except (ValueError, TypeError):
                pass
        
        # Create base account info object
        account_info = {
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
            "objectId": user.get("objectId"),
            "accountEnabled": user.get("accountEnabled", True),
            "staleLogin": False,
            "stalePassword": False
        }
        
        # Check for stale login
        if last_login and last_login < cutoff_date:
            account_is_stale = True
            account_info["staleLogin"] = True
            account_info["lastLoginActivity"] = last_login.isoformat()
            account_info["daysSinceLogin"] = (today - last_login).days
            stale_login_accounts.append(account_info.copy())
        
        # Check for stale password
        if last_password_change and last_password_change < cutoff_date:
            account_is_stale = True
            account_info["stalePassword"] = True
            account_info["lastPasswordChange"] = last_password_change.isoformat()
            account_info["daysSincePasswordChange"] = (today - last_password_change).days
            stale_password_accounts.append(account_info.copy())
        
        # Track enabled stale accounts
        if account_is_stale and user.get("accountEnabled", True):
            enabled_stale_accounts.append(account_info)
    
    # Remove duplicates from enabled_stale_accounts by objectId
    unique_enabled_stale = {}
    for account in enabled_stale_accounts:
        unique_enabled_stale[account["objectId"]] = account
    
    return {
        "totalUsers": total_users,
        "staleLoginAccounts": stale_login_accounts,
        "staleLoginAccountCount": len(stale_login_accounts),
        "stalePasswordAccounts": stale_password_accounts,
        "stalePasswordAccountCount": len(stale_password_accounts),
        "enabledStaleAccounts": list(unique_enabled_stale.values()),
        "enabledStaleAccountCount": len(unique_enabled_stale),
        "staleLoginPercentage": round(len(stale_login_accounts) / total_users * 100, 2) if total_users > 0 else 0,
        "stalePasswordPercentage": round(len(stale_password_accounts) / total_users * 100, 2) if total_users > 0 else 0
    }

@mcp.tool()
async def analyze_pim_implementation() -> Dict[str, Any]:
    """Analyze whether Privileged Identity Management (PIM) is implemented for just-in-time admin access"""
    # Get role definitions and assignments
    role_definitions = await call_roadrecon_api("roledefinitions")
    
    # Check for PIM implementation
    permanent_assignments = 0
    eligible_assignments = 0
    high_privilege_permanent = []
    
    high_privilege_roles = [
        "Global Administrator", 
        "Privileged Role Administrator",
        "Conditional Access Administrator",
        "Security Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "User Administrator",
        "Application Administrator"
    ]
    
    for role in role_definitions:
        # Check if this is a high-privilege role
        is_high_privilege = role.get("displayName") in high_privilege_roles
        
        # Count permanent and eligible assignments
        role_permanent_assignments = 0
        role_eligible_assignments = 0
        
        for assignment in role.get("assignments", []):
            if assignment.get("type") == "assignment":
                role_permanent_assignments += 1
                permanent_assignments += 1
                
                # Record high privilege permanent assignments
                if is_high_privilege and assignment.get("principal"):
                    high_privilege_permanent.append({
                        "roleName": role.get("displayName"),
                        "principalType": assignment.get("principal", {}).get("objectType"),
                        "principalName": assignment.get("principal", {}).get("displayName"),
                        "principalId": assignment.get("principal", {}).get("objectId")
                    })
            elif assignment.get("type") == "eligible":
                role_eligible_assignments += 1
                eligible_assignments += 1
    
    # Determine if PIM is effectively implemented
    pim_implemented = eligible_assignments > 0
    pim_effectively_implemented = pim_implemented and len(high_privilege_permanent) == 0
    
    return {
        "pimImplemented": pim_implemented,
        "pimEffectivelyImplemented": pim_effectively_implemented,
        "permanentAssignments": permanent_assignments,
        "eligibleAssignments": eligible_assignments,
        "highPrivilegePermanentAssignments": high_privilege_permanent,
        "highPrivilegePermanentCount": len(high_privilege_permanent),
        "recommendations": [
            "Implement PIM for all privileged roles" if not pim_implemented else "",
            "Convert permanent assignments to eligible assignments for high-privilege roles" if len(high_privilege_permanent) > 0 else ""
        ]
    }

@mcp.tool()
async def analyze_service_principal_credentials() -> Dict[str, Any]:
    """Analyze service principals for over-permissioned credentials with long expiration times"""
    service_principals = await call_roadrecon_api("serviceprincipals")
    
    today = datetime.now()
    long_expiry_threshold_days = 365  # 1 year
    risk_threshold_days = 730  # 2 years
    
    risky_sps = []
    total_sps_with_credentials = 0
    total_credentials = 0
    long_expiry_credentials = 0
    
    for sp in service_principals:
        # Get credentials from the service principal
        key_credentials = sp.get("keyCredentials", [])
        password_credentials = sp.get("passwordCredentials", [])
        
        if not key_credentials and not password_credentials:
            continue
            
        total_sps_with_credentials += 1
        total_sp_credentials = len(key_credentials) + len(password_credentials)
        total_credentials += total_sp_credentials
        
        # Check each credential
        sp_has_risky_credential = False
        risky_credentials = []
        
        # Check key credentials (certificates)
        for cred in key_credentials:
            if not cred.get("endDate"):
                continue
                
            try:
                end_date = datetime.fromisoformat(cred.get("endDate").replace('Z', '+00:00'))
                days_until_expiry = (end_date - today).days
                
                if days_until_expiry > long_expiry_threshold_days:
                    long_expiry_credentials += 1
                    
                if days_until_expiry > risk_threshold_days:
                    sp_has_risky_credential = True
                    risky_credentials.append({
                        "type": "certificate",
                        "daysUntilExpiry": days_until_expiry,
                        "expiryDate": end_date.isoformat()
                    })
            except (ValueError, TypeError):
                pass
        
        # Check password credentials (client secrets)
        for cred in password_credentials:
            if not cred.get("endDate"):
                continue
                
            try:
                end_date = datetime.fromisoformat(cred.get("endDate").replace('Z', '+00:00'))
                days_until_expiry = (end_date - today).days
                
                if days_until_expiry > long_expiry_threshold_days:
                    long_expiry_credentials += 1
                    
                if days_until_expiry > risk_threshold_days:
                    sp_has_risky_credential = True
                    risky_credentials.append({
                        "type": "password",
                        "daysUntilExpiry": days_until_expiry,
                        "expiryDate": end_date.isoformat()
                    })
            except (ValueError, TypeError):
                pass
        
        # If this SP has any risky credentials, add it to our list
        if sp_has_risky_credential:
            # Check for high permissions
            high_permissions = False
            app_roles = sp.get("appRolesAssigned", [])
            oauth_permissions = sp.get("oauth2Permissions", [])
            
            if app_roles or oauth_permissions:
                high_permissions = True
            
            # Check if member of privileged roles
            is_privileged = False
            directory_roles = sp.get("memberOfRole", [])
            for role in directory_roles:
                if role.get("displayName") in ["Global Administrator", "Application Administrator", "Cloud Application Administrator"]:
                    is_privileged = True
                    break
            
            risky_sps.append({
                "displayName": sp.get("displayName"),
                "objectId": sp.get("objectId"),
                "appId": sp.get("appId"),
                "servicePrincipalType": sp.get("servicePrincipalType"),
                "totalCredentials": total_sp_credentials,
                "riskyCredentials": risky_credentials,
                "hasHighPermissions": high_permissions,
                "isPrivileged": is_privileged
            })
    
    return {
        "totalServicePrincipalsWithCredentials": total_sps_with_credentials,
        "totalCredentials": total_credentials,
        "longExpiryCredentials": long_expiry_credentials,
        "riskyServicePrincipals": risky_sps,
        "riskyServicePrincipalCount": len(risky_sps)
    }

@mcp.tool()
async def analyze_legacy_authentication() -> Dict[str, Any]:
    """Analyze for potential legacy authentication protocols that bypass MFA"""
    # Get authorization policies which may contain legacy auth settings
    auth_policies = await call_roadrecon_api("authorizationpolicies")
    tenant_details = await call_roadrecon_api("tenantdetails")
    
    # Check if legacy authentication is blocked
    legacy_auth_blocked = False
    
    for policy in auth_policies:
        if policy.get("defaultUserRolePermissions", {}).get("allowedToSignInOnPortal") is False:
            legacy_auth_blocked = True
            break
    
    # Get users to check for potential legacy auth
    users = await call_roadrecon_api("users")
    mfa_data = await call_roadrecon_api("mfa")
    
    # Create lookup for MFA status
    mfa_lookup = {}
    for user in mfa_data:
        mfa_lookup[user.get("objectId")] = {
            "hasMfa": user.get("mfamethods", 0) > 0,
            "perusermfa": user.get("perusermfa")
        }
    
    # Identify users at risk
    at_risk_users = []
    mail_enabled_users = 0
    
    for user in users:
        # Skip disabled accounts
        if not user.get("accountEnabled", True):
            continue
            
        # Check if user has mailbox
        has_mail = bool(user.get("mail"))
        if has_mail:
            mail_enabled_users += 1
            
            # Check if user has MFA
            user_id = user.get("objectId")
            has_mfa = mfa_lookup.get(user_id, {}).get("hasMfa", False)
            
            if not has_mfa:
                at_risk_users.append({
                    "displayName": user.get("displayName"),
                    "userPrincipalName": user.get("userPrincipalName"),
                    "objectId": user_id,
                    "hasMail": True,
                    "hasMfa": False
                })
    
    return {
        "legacyAuthenticationBlocked": legacy_auth_blocked,
        "mailEnabledUsers": mail_enabled_users,
        "usersAtRiskOfLegacyAuth": at_risk_users,
        "usersAtRiskCount": len(at_risk_users),
        "tenantCreationDate": tenant_details.get("createdDateTime", "Unknown"),
        "recommendations": [
            "Block legacy authentication through Conditional Access or Security Defaults" if not legacy_auth_blocked else "",
            "Enable MFA for all users, especially those with mailboxes" if len(at_risk_users) > 0 else "",
            "Implement Conditional Access policies to block legacy authentication protocols" if not legacy_auth_blocked else ""
        ]
    }

@mcp.tool()
async def analyze_conditional_access_policies() -> Dict[str, Any]:
    """Analyze conditional access policies for security gaps and best practice alignment"""
    # Note: ROADrecon doesn't directly expose Conditional Access policies via its API,
    # but we can infer some information from authorization policies and other settings
    
    auth_policies = await call_roadrecon_api("authorizationpolicies")
    tenant_details = await call_roadrecon_api("tenantdetails")
    mfa_data = await call_roadrecon_api("mfa")
    
    # Check for security defaults (an alternative to conditional access in some tenants)
    security_defaults_enabled = False
    for policy in auth_policies:
        if policy.get("enabledPreviewFeatures") and "SecurityDefaults" in policy.get("enabledPreviewFeatures"):
            security_defaults_enabled = True
            break
    
    # Analyze MFA enforcement
    total_users = len(mfa_data)
    users_with_mfa = sum(1 for user in mfa_data if user.get("mfamethods", 0) > 0)
    mfa_percentage = round((users_with_mfa / total_users) * 100, 2) if total_users > 0 else 0
    
    # Check for per-user MFA (legacy) vs. Conditional Access MFA
    per_user_mfa_count = sum(1 for user in mfa_data if user.get("perusermfa") == "enabled")
    likely_using_ca_for_mfa = users_with_mfa > per_user_mfa_count
    
    # Identify potential gaps in coverage
    users_without_mfa = [
        {
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
            "objectId": user.get("objectId")
        }
        for user in mfa_data 
        if user.get("accountEnabled", True) and user.get("mfamethods", 0) == 0
    ]
    
    # Check for advanced security settings
    advanced_settings = {
        "legacyAuthenticationBlocked": any(
            policy.get("defaultUserRolePermissions", {}).get("allowedToSignInOnPortal") is False
            for policy in auth_policies
        ),
        "registrationRequired": any(
            policy.get("authenticationMethodsPolicy", {}).get("registrationEnforcement", {}).get("authenticationMethodsRequiredForRegistration", [])
            for policy in auth_policies
        ),
        "securityDefaultsEnabled": security_defaults_enabled
    }
    
    # Construct recommendations based on findings
    recommendations = []
    
    if not advanced_settings["legacyAuthenticationBlocked"]:
        recommendations.append("Implement Conditional Access policies to block legacy authentication protocols")
    
    if mfa_percentage < 90:
        recommendations.append(f"Increase MFA coverage from {mfa_percentage}% to at least 90% of accounts")
    
    if per_user_mfa_count > 0:
        recommendations.append("Replace legacy per-user MFA with Conditional Access-based MFA policies")
    
    if not security_defaults_enabled and not likely_using_ca_for_mfa:
        recommendations.append("Enable Security Defaults if not using Conditional Access policies")
    
    if len(users_without_mfa) > 0:
        recommendations.append("Implement a Conditional Access policy requiring MFA for all users")
    
    # Tenant maturity assessment
    if security_defaults_enabled:
        maturity_level = "Basic"
        maturity_description = "Using Security Defaults for baseline protection"
    elif likely_using_ca_for_mfa and advanced_settings["legacyAuthenticationBlocked"]:
        maturity_level = "Advanced"
        maturity_description = "Using Conditional Access policies with modern authentication enforcement"
    elif mfa_percentage > 80:
        maturity_level = "Intermediate"
        maturity_description = "Good MFA coverage but may lack comprehensive Conditional Access policies"
    else:
        maturity_level = "Minimal"
        maturity_description = "Limited security controls detected"
    
    return {
        "conditionalAccessMaturity": {
            "level": maturity_level,
            "description": maturity_description
        },
        "mfaEnforcement": {
            "totalUsers": total_users,
            "usersWithMfa": users_with_mfa,
            "mfaPercentage": mfa_percentage,
            "perUserMfaCount": per_user_mfa_count,
            "likelyUsingConditionalAccessForMfa": likely_using_ca_for_mfa
        },
        "securitySettings": advanced_settings,
        "securityGaps": {
            "usersWithoutMfa": len(users_without_mfa),
            "usersWithoutMfaSample": users_without_mfa[:10]  # Limit to avoid large payload
        },
        "recommendations": recommendations,
        "bestPractices": [
            "Implement MFA for all users through Conditional Access",
            "Block legacy authentication protocols",
            "Enforce device compliance for access to sensitive data",
            "Use risk-based Conditional Access policies",
            "Require MFA for all administrative actions",
            "Restrict access based on location/network"
        ]
    }

# Prompts for security analysis
@mcp.prompt()
def analyze_security_posture(tenant_name: str = "") -> str:
    """Prompt to analyze the overall security posture of the Azure AD tenant"""
    return f"""Analyze the security posture of the Azure AD tenant{f' {tenant_name}' if tenant_name else ''} by examining the following aspects:

1. Review the tenant details for security-related configurations
2. Analyze MFA adoption across users
3. Identify privileged users and evaluate their security status
4. Examine application registrations for security risks
5. Analyze service principals and their permissions
6. Review directory roles for potential over-privileged accounts

Please identify security risks, recommend mitigations, and highlight any critical issues that require immediate attention.
"""

@mcp.prompt()
def analyze_privileged_access() -> str:
    """Prompt to analyze privileged access in the Azure AD tenant"""
    return """Analyze the privileged access model in this Azure AD tenant by:

1. Identifying all Global Administrators and other high-privilege role holders
2. Evaluating whether the number of privileged users follows the principle of least privilege
3. Checking if privileged accounts have proper security controls (MFA, PIM, etc.)
4. Identifying service principals with high permissions
5. Looking for potential privilege escalation paths

Please provide specific recommendations to improve the privileged access security posture.
"""

@mcp.prompt()
def investigate_application_risks() -> str:
    """Prompt to investigate application security risks"""
    return """Investigate application security risks in this Azure AD tenant by:

1. Identifying applications with client secrets and certificates
2. Analyzing OAuth permissions granted to applications
3. Identifying multi-tenant applications that could pose security risks
4. Examining app role assignments for over-privileged service principals
5. Looking for applications with suspicious or excessive permissions

Please provide a risk assessment for the applications discovered and recommend security improvements.
"""

@mcp.prompt()
def analyze_identity_security() -> str:
    """Prompt to analyze identity security configurations"""
    return """Analyze the identity security configuration in this Azure AD tenant by:

1. Evaluating MFA deployment status across all users
2. Reviewing account lockout policies
3. Identifying accounts with legacy authentication methods
4. Examining password policies and configurations
5. Analyzing conditional access policies if available

Please highlight security gaps and provide recommendations aligned with identity security best practices.
"""

@mcp.prompt()
def analyze_stale_accounts() -> str:
    """Prompt to analyze stale accounts that may pose security risks"""
    return """Analyze stale user accounts in this Azure AD tenant by:

1. Identifying accounts that have not logged in within the last 90 days
2. Determining if these stale accounts have privileged access
3. Checking if stale accounts are still enabled and could be used for unauthorized access
4. Evaluating the risk posed by these accounts
5. Recommending account lifecycle management processes

Please provide specific recommendations for addressing stale accounts and implementing proper account lifecycle management.
"""

@mcp.prompt()
def analyze_privileged_access_management() -> str:
    """Prompt to analyze privileged access management including PIM implementation"""
    return """Analyze the privileged access management in this Azure AD tenant by:

1. Determining if Privileged Identity Management (PIM) is implemented for just-in-time admin access
2. Identifying privileged roles with permanent assignments instead of eligible assignments
3. Evaluating the number of users with permanent administrative access
4. Assessing governance controls for privileged accounts
5. Recommending improvements to implement least-privilege principles

Please provide specific recommendations to improve privileged access security through PIM and other controls.
"""

@mcp.prompt()
def analyze_service_principal_security() -> str:
    """Prompt to analyze service principal and application security risks"""
    return """Analyze service principal and application security in this Azure AD tenant by:

1. Identifying service principals with credentials that have excessively long expiration periods
2. Checking for service principals with both high permissions and long-lived credentials
3. Evaluating whether service principals follow least-privilege principles
4. Assessing credential management practices for applications
5. Recommending improvements to application and service principal security

Please provide specific recommendations to reduce risks associated with service principal credentials and permissions.
"""

@mcp.prompt()
def analyze_legacy_authentication_risks() -> str:
    """Prompt to analyze risks from legacy authentication protocols"""
    return """Analyze the risks from legacy authentication protocols in this Azure AD tenant by:

1. Determining if legacy authentication protocols are blocked
2. Identifying users who could authenticate using legacy protocols that bypass MFA
3. Assessing the risk to mail-enabled accounts from legacy auth
4. Evaluating existing controls that might mitigate these risks
5. Recommending improvements to block or monitor legacy authentication attempts

Please provide specific recommendations to protect against attacks that use legacy authentication protocols.
"""

@mcp.prompt()
def analyze_conditional_access() -> str:
    """Prompt to analyze conditional access policies and gaps"""
    return """Analyze the Conditional Access implementation in this Azure AD tenant by:

1. Assessing the current maturity level of Conditional Access usage
2. Identifying gaps in MFA enforcement through Conditional Access
3. Evaluating legacy authentication blocking
4. Checking for use of Security Defaults vs. custom Conditional Access policies
5. Analyzing whether risk-based Conditional Access is implemented

Please provide recommendations to improve the security posture through better Conditional Access policies, with specific focus on:
- Moving from legacy per-user MFA to Conditional Access-based MFA
- Blocking legacy authentication protocols
- Implementing Zero Trust principles
- Addressing any coverage gaps for critical applications and users
"""

@mcp.prompt()
def comprehensive_security_review() -> str:
    """Prompt for a comprehensive security review of the Azure AD environment"""
    return """Perform a comprehensive security review of this Azure AD environment by analyzing:

1. Identity Security
   - MFA deployment and gaps
   - Password policies and account protection
   - Legacy authentication risks
   - Conditional access policies

2. Privileged Access Management
   - PIM implementation status
   - Privileged role assignments (permanent vs. eligible)
   - Principle of least privilege adherence
   - Administrative account security

3. Application Security
   - Service principal credential management
   - OAuth permissions and consent grants
   - App role assignments and permissions
   - Multi-tenant application risks

4. Account Lifecycle Management
   - Stale account detection and management
   - Guest user access and security
   - Service account governance
   - Account provisioning/deprovisioning processes

For each area, identify key risks, provide specific recommendations, and suggest prioritized remediation actions.
"""

if __name__ == "__main__":
    # Run the server
    mcp.run()
