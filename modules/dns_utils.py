import concurrent.futures
import dns.resolver
import random
import string
import os
import yaml
import time
import requests
import logging
from typing import Dict, Any

from .reporting import console
from .web_analysis import check_webpage_content

logger = logging.getLogger(__name__)


def load_dns_integrations(yaml_path: str = "dns_integrations.yaml") -> Dict[str, str]:
    """Load DNS integration patterns from YAML file with error handling."""
    if not os.path.exists(yaml_path):
        console.print(f"[bold red]Error:[/bold red] YAML file not found: {yaml_path}")
        console.print(f"Creating sample YAML file at {yaml_path}")
        sample_data = {
            "AWS IAM Identity Center": "SHORT_NAME.awsapps.com",
            "Absorb LMS": "SHORT_NAME.myabsorb.com",
            "Adobe Workfront": "SHORT_NAME.my.workfront.com",
            "Asana": "SHORT_NAME.asana.com",
            "Atlassian (Jira/Confluence)": "SHORT_NAME.atlassian.net",
        }
        with open(yaml_path, "w") as f:
            yaml.dump(sample_data, f)
        return sample_data

    try:
        with open(yaml_path, "r") as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        console.print(f"[bold red]Error:[/bold red] Failed to parse YAML file: {str(e)}")
        raise


def generate_random_subdomain(length: int = 12) -> str:
    """Generate a random subdomain for comparison testing."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def resolve_hostname(hostname: str, timeout: int = 5) -> Dict[str, Any]:
    """Attempt to resolve a hostname to IP addresses or CNAME records with timeout."""
    results = {}

    def query_with_timeout(qtype: str):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(hostname, qtype)
            return sorted([str(rdata) for rdata in answers])
        except Exception:
            return []

    results["A"] = query_with_timeout("A")
    results["CNAME"] = query_with_timeout("CNAME")
    results["MX"] = query_with_timeout("MX")
    results["TXT"] = query_with_timeout("TXT")

    all_records = []
    for records in results.values():
        all_records.extend(records)

    return {"all": all_records, "details": results}


def dns_check(provider: str, domain_template: str, short_name: str, timeout: int = 10) -> Dict[str, Any]:
    """Perform a comprehensive check for a given provider."""
    start_time = time.time()

    random_name = generate_random_subdomain()
    fake_hostname = domain_template.replace("SHORT_NAME", random_name)
    real_hostname = domain_template.replace("SHORT_NAME", short_name)

    result = {
        "provider": provider,
        "hostname": real_hostname,
        "status": "",
        "message": "",
        "dns_result": None,
        "web_check": {
            "performed": False,
            "url_checked": None,
            "final_url": None,
            "reference_found": False,
            "details": None,
            "text_snippets": [],
            "page_title": None,
            "html_excerpt": None,
            "has_forms": False,
            "word_count": 0,
            "evidence": [],
            "match_strength": "none",
        },
    }

    if time.time() - start_time > timeout * 0.5:
        result["status"] = "timeout"
        result["message"] = "Initial setup took too long, skipping provider"
        return result

    dns_timeout = min(3, timeout * 0.3)

    try:
        fake_result = resolve_hostname(fake_hostname, timeout=dns_timeout)
    except Exception as e:
        logger.warning(f"Failed to resolve fake hostname {fake_hostname}: {e}")
        fake_result = {"all": [], "details": {}}

    if time.time() - start_time > timeout * 0.7:
        result["status"] = "timeout"
        result["message"] = "DNS resolution took too long, skipping further checks"
        return result

    try:
        real_result = resolve_hostname(real_hostname, timeout=dns_timeout)
    except Exception as e:
        logger.warning(f"Failed to resolve real hostname {real_hostname}: {e}")
        real_result = {"all": [], "details": {}}

    result["dns_result"] = real_result

    if not real_result["all"]:
        result["status"] = "no_record"
        result["message"] = "No DNS record found."
        return result

    is_wildcard = fake_result["all"] == real_result["all"] and real_result["all"]

    if is_wildcard:
        result["status"] = "wildcard_match"
        result["message"] = "Wildcard DNS match detected (same as random subdomain). Likely not legitimate."
    else:
        result["status"] = "valid_dns"
        result["message"] = f"Valid DNS entry found: {', '.join(real_result['all'][:2])}"

    remaining_time = timeout - (time.time() - start_time)
    if remaining_time < 2:
        result["web_check"]["details"] = "Skipped web check due to timeout"
        return result

    try:
        urls_to_try = [f"https://{real_hostname}", f"http://{real_hostname}"]
        result["web_check"]["performed"] = True
        web_timeout = min(remaining_time * 0.8, 8)
        last_error = None
        for url in urls_to_try:
            try:
                result["web_check"]["url_checked"] = url
                has_reference, details, final_url, match_strength = check_webpage_content(
                    url, short_name, result, timeout=web_timeout
                )
                result["web_check"]["reference_found"] = has_reference
                result["web_check"]["details"] = details
                result["web_check"]["final_url"] = final_url
                result["web_check"]["match_strength"] = match_strength

                # Check for SSO redirect in evidence
                has_sso_redirect = any("SSO redirect detected" in evidence for evidence in result["web_check"]["evidence"])

                if has_reference:
                    if match_strength == "strong":
                        if is_wildcard:
                            result["status"] = "confirmed_via_web"
                            if has_sso_redirect:
                                result["message"] = "DNS wildcard - SSO redirect"
                            else:
                                result["message"] = "DNS wildcard - company name found in page content"
                        else:
                            result["status"] = "confirmed_valid"
                            if has_sso_redirect:
                                result["message"] = "DNS valid - SSO redirect"
                            else:
                                result["message"] = "DNS valid - company name found in page content"
                    elif match_strength == "weak":
                        if is_wildcard:
                            result["status"] = "url_only_match"
                            if has_sso_redirect:
                                result["message"] = "DNS wildcard - SSO redirect (weak evidence)"
                            else:
                                result["message"] = "DNS wildcard - company name only in URL (weak evidence)"
                        else:
                            result["status"] = "url_only_match"
                            if has_sso_redirect:
                                result["message"] = "DNS valid - SSO redirect (weak evidence)"
                            else:
                                result["message"] = "DNS valid - company name only in URL (weak evidence)"
                else:
                    if not is_wildcard:
                        result["status"] = "dns_only_match"
                        result["message"] = "DNS valid - company name not found anywhere"
                break
            except requests.RequestException as e:
                last_error = str(e)
                continue
        else:
            result["web_check"]["details"] = f"All web requests failed. Last error: {last_error}"
            result["web_check"]["match_strength"] = "none"
    except Exception as e:
        result["web_check"]["details"] = f"Web check error: {str(e)}"
        result["web_check"]["match_strength"] = "none"
        logger.warning(f"Web check error for {real_hostname}: {str(e)}")

    return result


def check_dns_providers(yaml_path: str = "dns_integrations.yaml"):
    """Check all DNS providers for liveness"""
    DNS_INTEGRATIONS = load_dns_integrations(yaml_path)

    console.print(f"[bold]Checking {len(DNS_INTEGRATIONS)} DNS providers for liveness...[/bold]")

    results = []
    random_name = generate_random_subdomain()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        for provider, domain_template in DNS_INTEGRATIONS.items():
            hostname = domain_template.replace("SHORT_NAME", random_name)
            futures[executor.submit(resolve_hostname, hostname)] = (provider, hostname)

        for future in concurrent.futures.as_completed(futures):
            provider, hostname = futures[future]
            try:
                dns_result = future.result()
                is_wildcard = bool(dns_result["all"])
                results.append({
                    "provider": provider,
                    "hostname": hostname,
                    "is_wildcard": is_wildcard,
                    "dns_result": dns_result,
                })
            except Exception as e:
                logger.error(f"Error checking provider {provider}: {str(e)}")

    wildcard_count = sum(1 for r in results if r["is_wildcard"])

    from rich.table import Table

    table = Table(title="DNS Provider Wildcard Check Results")
    table.add_column("Provider", style="cyan")
    table.add_column("Test Hostname")
    table.add_column("Wildcard?", justify="center")

    for result in results:
        wildcard_text = "YES" if result["is_wildcard"] else "NO"
        wildcard_style = "red" if result["is_wildcard"] else "green"
        table.add_row(result["provider"], result["hostname"], f"[{wildcard_style}]{wildcard_text}[/{wildcard_style}]")

    console.print(table)
    console.print(f"\n[bold]Summary:[/bold] {wildcard_count} out of {len(results)} providers use wildcard DNS.")

    return results
