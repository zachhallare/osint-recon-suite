"""Target resolution logic for converting company names to domains."""

import logging
import httpx

logger = logging.getLogger(__name__)

class AmbiguousResolutionError(ValueError):
    def __init__(self, message, candidates):
        super().__init__(message)
        self.candidates = candidates

async def resolve_target(target: str) -> tuple[str, str | None, bool]:
    """
    Takes a target string and returns (resolved_domain, company_name, is_resolved).
    If it looks like a domain, returns it unchanged.
    If it's a company name, queries Clearbit Autocomplete.
    Raises ValueError if not found.
    Raises AmbiguousResolutionError if multiple candidates are found.
    Raises RuntimeError on network failure.
    """
    clean_target = target.strip()
    
    # Simple heuristic: if it contains a dot and no spaces, treat as domain
    if "." in clean_target and " " not in clean_target:
        return clean_target, None, False

    logger.info("Attempting to resolve company name '%s' to a domain...", clean_target)
    
    url = f"https://autocomplete.clearbit.com/v1/companies/suggest?query={clean_target}"
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
    except httpx.RequestError as e:
        logger.error("Network error during domain resolution: %s", e)
        raise RuntimeError(f"Network error resolving target: {e}") from e
    except Exception as e:
        logger.error("Failed to parse resolution response: %s", e)
        raise RuntimeError(f"Unexpected error resolving target: {e}") from e

    if not data:
        raise ValueError(f"Could not resolve company name '{clean_target}' to a domain.")

    if len(data) > 1:
        raise AmbiguousResolutionError(
            f"Multiple candidates found for '{clean_target}'.",
            candidates=data
        )

    # Pick the top result
    top_result = data[0]
    resolved_domain = top_result.get("domain")
    company_name = top_result.get("name")
    
    if not resolved_domain:
        raise ValueError(f"Clearbit returned a result without a domain for '{clean_target}'.")

    logger.info("Successfully resolved '%s' to '%s'", clean_target, resolved_domain)
    return resolved_domain, company_name, True
