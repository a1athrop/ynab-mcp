#!/usr/bin/env python3
"""
YNAB MCP Server

Exposes YNAB (You Need A Budget) operations as MCP tools, allowing
Claude (or any MCP client) to manage budgets, accounts, categories,
transactions, and more.

Configuration via environment variables:
    YNAB_ACCESS_TOKEN      - Personal Access Token (from https://app.ynab.com/settings)
    YNAB_DEFAULT_BUDGET_ID - Default budget ID (optional; uses "last-used" or auto-detects)

Multi-user support:
    YNAB_TOKEN_<USERNAME>  - Per-user token (e.g., YNAB_TOKEN_ADAM, YNAB_TOKEN_SARAH)

    Each user gets their own connector URL:
        /adam/mcp  → uses YNAB_TOKEN_ADAM
        /sarah/mcp → uses YNAB_TOKEN_SARAH
        /mcp       → uses YNAB_ACCESS_TOKEN (default)

Run locally:
    python server.py                              # stdio transport (for Claude Desktop)
    python server.py --transport streamable-http  # HTTP transport (for remote/Claude.ai)

Run with uv:
    uv run server.py --transport streamable-http
"""

import contextvars
import hmac
import json
import logging
import os
from datetime import date
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from dotenv import load_dotenv
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_server_dir = Path(__file__).resolve().parent
_skill_dir = _server_dir.parent
for _candidate in [_server_dir / ".env", _skill_dir / ".env"]:
    if _candidate.exists():
        load_dotenv(_candidate)
        break

YNAB_BASE_URL = "https://api.ynab.com/v1"
DEFAULT_TOKEN = os.environ.get("YNAB_ACCESS_TOKEN", "").strip()
DEFAULT_BUDGET_ID = os.environ.get("YNAB_DEFAULT_BUDGET_ID", "").strip()

# Bearer token for MCP endpoint authentication.
MCP_BEARER_TOKEN = os.environ.get("MCP_BEARER_TOKEN", "").strip()

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("ynab-mcp")

# ---------------------------------------------------------------------------
# Multi-User Token Support
# ---------------------------------------------------------------------------

USER_TOKENS: dict[str, str] = {}
_token_pattern = re.compile(r"^YNAB_TOKEN_([A-Z0-9_]+)$", re.IGNORECASE)

for key, value in os.environ.items():
    match = _token_pattern.match(key)
    if match and value.strip():
        username = match.group(1).lower()
        USER_TOKENS[username] = value.strip()
        logger.info("Loaded token for user: %s", username)

if USER_TOKENS:
    logger.info("Multi-user mode: %d user token(s) configured", len(USER_TOKENS))
else:
    logger.info("Single-user mode: using default YNAB_ACCESS_TOKEN")

_current_token: contextvars.ContextVar[str] = contextvars.ContextVar("current_token", default="")

# ---------------------------------------------------------------------------
# Bearer Token Authentication
# ---------------------------------------------------------------------------


class _StaticTokenVerifier:
    """Verify incoming Bearer tokens against a single shared secret."""

    def __init__(self, expected_token: str):
        self._expected = expected_token

    async def verify_token(self, token: str) -> AccessToken | None:
        if not self._expected or not hmac.compare_digest(token, self._expected):
            return None
        return AccessToken(
            token=token,
            client_id="mcp-client",
            scopes=["mcp:tools"],
            expires_at=None,
        )


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

_auth_kwargs: dict = {}
if MCP_BEARER_TOKEN:
    _auth_kwargs = {
        "auth": AuthSettings(
            issuer_url="https://auth.ynab-mcp.com",
            resource_server_url="https://mcp.ynab-mcp.com",
            required_scopes=["mcp:tools"],
        ),
        "token_verifier": _StaticTokenVerifier(MCP_BEARER_TOKEN),
    }
    logger.info("Bearer token authentication ENABLED")
else:
    logger.warning(
        "MCP_BEARER_TOKEN is not set — endpoint is UNAUTHENTICATED. "
        "Set MCP_BEARER_TOKEN to require Bearer auth on every request."
    )

mcp = FastMCP(
    "YNAB Budget Manager",
    instructions="""This server manages YNAB (You Need A Budget) budgets, accounts, categories, transactions, and scheduled transactions.

CRITICAL — Currency Format:
All monetary amounts in YNAB are in MILLIUNITS (1/1000 of a currency unit).
  - $10.00 = 10000 milliunits
  - -$5.50 = -5500 milliunits
  - $0.01 = 10 milliunits
When the user says "$50", convert to 50000 before calling any tool.
When displaying amounts from YNAB, convert back: divide by 1000 and format as currency.
NEVER show raw milliunit values to the user. Use the *_display fields in responses.

Date Format:
All dates use ISO 8601 format (YYYY-MM-DD). The "current month" in YNAB uses
the first of the month (e.g., "2026-02-01").

Default Budget:
Most tools accept an optional budget_id. When omitted, the server uses the
configured default budget or auto-detects a single budget.
Only pass budget_id explicitly if the user has multiple budgets and specifies which one.

Transaction Cleared Status:
  - "uncleared" — Transaction entered manually, not yet confirmed by bank
  - "cleared" — Transaction confirmed (matches bank import or manually cleared)
  - "reconciled" — Transaction locked after reconciliation
When creating transactions manually, default to "cleared" unless the user indicates otherwise.

Account Types:
  checking, savings, cash, creditCard, lineOfCredit, otherAsset, otherLiability,
  mortgage, autoLoan, studentLoan, personalLoan, medicalDebt, otherDebt

Flag Colors: red, orange, yellow, green, blue, purple

Scheduled Transaction Frequencies:
  never, daily, weekly, everyOtherWeek, twiceAMonth, every4Weeks,
  monthly, everyOtherMonth, every3Months, every4Months, twiceAYear,
  yearly, everyOtherYear

Rate Limiting:
The YNAB API allows 200 requests/hour. Prefer get_month over repeated
get_categories calls when you need monthly budget data.

Natural language hints for tool selection:
- "How much did I spend on..." / "show transactions for..." → get_transactions
- "What's my balance?" / "how much is in..." → get_accounts
- "How much is budgeted for..." / "what's left in..." → get_categories or get_month
- "Add a transaction" / "I spent..." / "I bought..." → create_transaction
- "Move money to..." / "budget more for..." → update_month_category
- "What's coming up?" / "scheduled..." / "recurring..." → get_scheduled_transactions
- "Show me this month" / "monthly overview" → get_month
""",
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
    **_auth_kwargs,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_token() -> str:
    """Return the current YNAB access token."""
    token = _current_token.get() or DEFAULT_TOKEN
    if not token:
        raise ValueError(
            "No YNAB access token available. Set YNAB_ACCESS_TOKEN (default) "
            "or YNAB_TOKEN_<USERNAME> environment variables."
        )
    return token


def _api_request(path: str, method: str = "GET", body: dict | list | None = None) -> dict:
    """Make a YNAB API request and return parsed JSON."""
    token = _get_token()
    url = f"{YNAB_BASE_URL}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else str(e)
        logger.error("YNAB API error: HTTP %d — %s (URL: %s)", e.code, error_body, url)

        # Try to extract YNAB's error detail
        detail = ""
        try:
            err_json = json.loads(error_body)
            detail = err_json.get("error", {}).get("detail", "")
        except (json.JSONDecodeError, AttributeError):
            pass

        friendly = {
            400: "Bad request — check that all parameter values are valid.",
            401: "Authentication failed — the YNAB access token may be expired or invalid.",
            403: "Permission denied — insufficient access to this resource.",
            404: "Not found — the budget, account, category, or transaction may not exist.",
            409: "Conflict — the resource may have been modified by someone else.",
            429: "Rate limited — YNAB allows 200 requests/hour. Please wait before trying again.",
            500: "YNAB server error — try again later.",
            503: "YNAB is temporarily unavailable — try again later.",
        }
        msg = friendly.get(e.code, f"YNAB API returned HTTP {e.code}.")
        if detail:
            msg = f"{msg} Detail: {detail}"
        raise RuntimeError(msg) from e
    except urllib.error.URLError as e:
        logger.error("Connection error to YNAB: %s (URL: %s)", e.reason, url)
        raise RuntimeError("Could not connect to YNAB API. Check server logs for details.") from e


def _resolve_budget_id(budget_id: Optional[str]) -> str:
    """Resolve budget_id from explicit param, env var, or auto-detect.

    Resolution order:
    1. Explicit budget_id parameter
    2. YNAB_DEFAULT_BUDGET_ID env var (if set and not "last-used")
    3. If "last-used", fetch budgets and pick most recently modified
    4. If only one budget exists, use it automatically
    5. Raise error asking user to specify
    """
    if budget_id:
        return budget_id

    if DEFAULT_BUDGET_ID and DEFAULT_BUDGET_ID != "last-used":
        return DEFAULT_BUDGET_ID

    # Auto-detect: fetch budgets
    result = _api_request("/budgets")
    budgets = result.get("data", {}).get("budgets", [])

    if not budgets:
        raise ValueError("No budgets found in this YNAB account.")

    if len(budgets) == 1:
        return budgets[0]["id"]

    if DEFAULT_BUDGET_ID == "last-used":
        # Pick the most recently modified budget
        budgets.sort(key=lambda b: b.get("last_modified_on", ""), reverse=True)
        return budgets[0]["id"]

    # Multiple budgets, no default configured
    budget_names = ", ".join(f'"{b["name"]}" ({b["id"]})' for b in budgets)
    raise ValueError(
        f"Multiple budgets found: {budget_names}. "
        "Set YNAB_DEFAULT_BUDGET_ID or pass budget_id explicitly."
    )


def _require_config():
    """Raise if YNAB_ACCESS_TOKEN is not set."""
    token = _current_token.get() or DEFAULT_TOKEN
    if not token:
        raise ValueError("Missing required environment variable: YNAB_ACCESS_TOKEN")


def _format_milliunits(amount: int | None) -> str:
    """Convert milliunits to display string: 50000 → '$50.00', -5500 → '-$5.50'."""
    if amount is None:
        return "$0.00"
    dollars = amount / 1000
    if dollars < 0:
        return f"-${abs(dollars):,.2f}"
    return f"${dollars:,.2f}"


def _current_month() -> str:
    """Return the current month as YYYY-MM-01."""
    today = date.today()
    return today.strftime("%Y-%m-01")


# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------

VALID_ACCOUNT_TYPES = {
    "checking", "savings", "cash", "creditCard", "lineOfCredit",
    "otherAsset", "otherLiability", "mortgage", "autoLoan",
    "studentLoan", "personalLoan", "medicalDebt", "otherDebt",
}

VALID_CLEARED_STATUSES = {"cleared", "uncleared", "reconciled"}

VALID_FLAG_COLORS = {"red", "orange", "yellow", "green", "blue", "purple"}

VALID_TRANSACTION_TYPES = {"uncategorized", "unapproved"}


def _validate_cleared(cleared: str | None) -> None:
    if cleared and cleared not in VALID_CLEARED_STATUSES:
        raise ValueError(
            f"Invalid cleared status: '{cleared}'. "
            f"Must be one of: {', '.join(sorted(VALID_CLEARED_STATUSES))}"
        )


def _validate_flag_color(flag_color: str | None) -> None:
    if flag_color and flag_color not in VALID_FLAG_COLORS:
        raise ValueError(
            f"Invalid flag color: '{flag_color}'. "
            f"Must be one of: {', '.join(sorted(VALID_FLAG_COLORS))}"
        )


def _validate_account_type(account_type: str) -> None:
    if account_type not in VALID_ACCOUNT_TYPES:
        raise ValueError(
            f"Invalid account type: '{account_type}'. "
            f"Must be one of: {', '.join(sorted(VALID_ACCOUNT_TYPES))}"
        )


# ---------------------------------------------------------------------------
# Tools — Core
# ---------------------------------------------------------------------------


@mcp.tool()
def get_budgets(
    include_accounts: bool = False,
) -> str:
    """List all budgets the user has access to.

    Args:
        include_accounts: If True, include account summaries for each budget.

    Returns:
        List of budgets with id, name, last_modified_on, and currency format.
    """
    _require_config()

    params = "?include_accounts=true" if include_accounts else ""
    result = _api_request(f"/budgets{params}")
    budgets_data = result.get("data", {}).get("budgets", [])

    budgets = []
    for b in budgets_data:
        budget_info = {
            "id": b.get("id"),
            "name": b.get("name"),
            "last_modified_on": b.get("last_modified_on"),
            "date_format": b.get("date_format", {}).get("format"),
            "currency_format": b.get("currency_format", {}).get("iso_code"),
        }
        if include_accounts:
            accounts = []
            for a in b.get("accounts", []):
                if a.get("deleted"):
                    continue
                accounts.append({
                    "id": a.get("id"),
                    "name": a.get("name"),
                    "type": a.get("type"),
                    "on_budget": a.get("on_budget"),
                    "closed": a.get("closed"),
                    "balance": a.get("balance"),
                    "balance_display": _format_milliunits(a.get("balance")),
                })
            budget_info["accounts"] = accounts
        budgets.append(budget_info)

    return json.dumps({"success": True, "count": len(budgets), "budgets": budgets}, indent=2)


@mcp.tool()
def get_accounts(
    budget_id: Optional[str] = None,
) -> str:
    """List all accounts in a budget with balances.

    Args:
        budget_id: Budget ID (uses default if omitted).

    Returns:
        List of accounts with name, type, balance, cleared_balance, on_budget, and closed status.
    """
    _require_config()
    bid = _resolve_budget_id(budget_id)

    result = _api_request(f"/budgets/{bid}/accounts")
    accounts_data = result.get("data", {}).get("accounts", [])

    accounts = []
    for a in accounts_data:
        if a.get("deleted"):
            continue
        accounts.append({
            "id": a.get("id"),
            "name": a.get("name"),
            "type": a.get("type"),
            "on_budget": a.get("on_budget"),
            "closed": a.get("closed"),
            "balance": a.get("balance"),
            "balance_display": _format_milliunits(a.get("balance")),
            "cleared_balance": a.get("cleared_balance"),
            "cleared_balance_display": _format_milliunits(a.get("cleared_balance")),
            "uncleared_balance": a.get("uncleared_balance"),
            "uncleared_balance_display": _format_milliunits(a.get("uncleared_balance")),
        })

    return json.dumps({
        "success": True,
        "count": len(accounts),
        "accounts": accounts,
        "server_knowledge": result.get("data", {}).get("server_knowledge"),
    }, indent=2)


@mcp.tool()
def get_categories(
    budget_id: Optional[str] = None,
) -> str:
    """List all category groups and categories with budgeted/activity/balance for the current month.

    Args:
        budget_id: Budget ID (uses default if omitted).

    Returns:
        Category groups with nested categories showing budgeted, activity, balance, and goal info.
    """
    _require_config()
    bid = _resolve_budget_id(budget_id)

    result = _api_request(f"/budgets/{bid}/categories")
    groups_data = result.get("data", {}).get("category_groups", [])

    groups = []
    for g in groups_data:
        if g.get("deleted") or g.get("hidden"):
            continue
        categories = []
        for c in g.get("categories", []):
            if c.get("deleted") or c.get("hidden"):
                continue
            categories.append({
                "id": c.get("id"),
                "name": c.get("name"),
                "budgeted": c.get("budgeted"),
                "budgeted_display": _format_milliunits(c.get("budgeted")),
                "activity": c.get("activity"),
                "activity_display": _format_milliunits(c.get("activity")),
                "balance": c.get("balance"),
                "balance_display": _format_milliunits(c.get("balance")),
                "goal_type": c.get("goal_type"),
                "goal_target": c.get("goal_target"),
                "goal_target_display": _format_milliunits(c.get("goal_target")),
                "goal_percentage_complete": c.get("goal_percentage_complete"),
            })
        if categories:
            groups.append({
                "id": g.get("id"),
                "name": g.get("name"),
                "categories": categories,
            })

    return json.dumps({
        "success": True,
        "category_groups": groups,
        "server_knowledge": result.get("data", {}).get("server_knowledge"),
    }, indent=2)


@mcp.tool()
def get_payees(
    budget_id: Optional[str] = None,
) -> str:
    """List all payees in a budget.

    Args:
        budget_id: Budget ID (uses default if omitted).

    Returns:
        List of payees with id and name.
    """
    _require_config()
    bid = _resolve_budget_id(budget_id)

    result = _api_request(f"/budgets/{bid}/payees")
    payees_data = result.get("data", {}).get("payees", [])

    payees = []
    for p in payees_data:
        if p.get("deleted"):
            continue
        payees.append({
            "id": p.get("id"),
            "name": p.get("name"),
        })

    return json.dumps({
        "success": True,
        "count": len(payees),
        "payees": payees,
        "server_knowledge": result.get("data", {}).get("server_knowledge"),
    }, indent=2)


@mcp.tool()
def get_month(
    month: Optional[str] = None,
    budget_id: Optional[str] = None,
) -> str:
    """Get a monthly budget summary with category breakdowns.

    Args:
        month: Month in YYYY-MM-DD format (first of month, e.g., "2026-02-01").
               Defaults to current month.
        budget_id: Budget ID (uses default if omitted).

    Returns:
        Month overview: income, budgeted, activity, to_be_budgeted, age_of_money,
        plus per-category details.
    """
    _require_config()
    bid = _resolve_budget_id(budget_id)
    m = month or _current_month()

    result = _api_request(f"/budgets/{bid}/months/{m}")
    month_data = result.get("data", {}).get("month", {})

    categories = []
    for c in month_data.get("categories", []):
        if c.get("deleted") or c.get("hidden"):
            continue
        categories.append({
            "id": c.get("id"),
            "name": c.get("name"),
            "category_group_name": c.get("category_group_name"),
            "budgeted": c.get("budgeted"),
            "budgeted_display": _format_milliunits(c.get("budgeted")),
            "activity": c.get("activity"),
            "activity_display": _format_milliunits(c.get("activity")),
            "balance": c.get("balance"),
            "balance_display": _format_milliunits(c.get("balance")),
        })

    return json.dumps({
        "success": True,
        "month": month_data.get("month"),
        "income": month_data.get("income"),
        "income_display": _format_milliunits(month_data.get("income")),
        "budgeted": month_data.get("budgeted"),
        "budgeted_display": _format_milliunits(month_data.get("budgeted")),
        "activity": month_data.get("activity"),
        "activity_display": _format_milliunits(month_data.get("activity")),
        "to_be_budgeted": month_data.get("to_be_budgeted"),
        "to_be_budgeted_display": _format_milliunits(month_data.get("to_be_budgeted")),
        "age_of_money": month_data.get("age_of_money"),
        "categories": categories,
    }, indent=2)


@mcp.tool()
def get_transactions(
    budget_id: Optional[str] = None,
    since_date: Optional[str] = None,
    before_date: Optional[str] = None,
    type: Optional[str] = None,
    account_id: Optional[str] = None,
    category_id: Optional[str] = None,
    payee_id: Optional[str] = None,
    max_results: int = 200,
) -> str:
    """Search and list transactions with optional filters.

    Args:
        budget_id: Budget ID (uses default if omitted).
        since_date: Only return transactions on or after this date (YYYY-MM-DD).
        before_date: Only return transactions before this date (YYYY-MM-DD). Server-side filter.
                     Use with since_date for a date range, e.g. since_date="2024-02-01",
                     before_date="2024-03-01" for all February 2024 transactions.
        type: Filter by "uncategorized" or "unapproved".
        account_id: Filter to a specific account.
        category_id: Filter to a specific category.
        payee_id: Filter to a specific payee.
        max_results: Maximum transactions to return (default 200).

    Returns:
        List of transactions with date, amount, payee, category, memo, cleared status.
        Includes truncated flag and total_available count when results are capped.
    """
    _require_config()
    bid = _resolve_budget_id(budget_id)

    # Build query params (only since_date is supported by YNAB API natively)
    params = []
    if since_date:
        params.append(f"since_date={urllib.parse.quote(since_date)}")
    if type:
        if type not in VALID_TRANSACTION_TYPES:
            return json.dumps({
                "success": False,
                "error": f"Invalid type: '{type}'. Must be 'uncategorized' or 'unapproved'.",
            })
        params.append(f"type={urllib.parse.quote(type)}")

    query = f"?{'&'.join(params)}" if params else ""

    # Dispatch to the appropriate sub-endpoint
    if account_id:
        path = f"/budgets/{bid}/accounts/{account_id}/transactions{query}"
    elif category_id:
        path = f"/budgets/{bid}/categories/{category_id}/transactions{query}"
    elif payee_id:
        path = f"/budgets/{bid}/payees/{payee_id}/transactions{query}"
    else:
        path = f"/budgets/{bid}/transactions{query}"

    result = _api_request(path)
    txns_data = result.get("data", {}).get("transactions", [])

    # Server-side before_date filter (YNAB API doesn't support this natively)
    if before_date:
        txns_data = [t for t in txns_data if t.get("date", "") < before_date]

    # Track total before truncation
    total_available = len(txns_data)

    # Limit results — return FIRST N (oldest) when since_date is set,
    # LAST N (most recent) otherwise. This ensures date-range queries
    # get the earliest matching transactions, not the latest.
    if len(txns_data) > max_results:
        if since_date:
            txns_data = txns_data[:max_results]  # First N (oldest)
        else:
            txns_data = txns_data[-max_results:]  # Last N (most recent)

    transactions = []
    for t in txns_data:
        txn = {
            "id": t.get("id"),
            "date": t.get("date"),
            "amount": t.get("amount"),
            "amount_display": _format_milliunits(t.get("amount")),
            "payee_id": t.get("payee_id"),
            "payee_name": t.get("payee_name"),
            "category_id": t.get("category_id"),
            "category_name": t.get("category_name"),
            "memo": t.get("memo"),
            "cleared": t.get("cleared"),
            "approved": t.get("approved"),
            "flag_color": t.get("flag_color"),
            "account_id": t.get("account_id"),
            "account_name": t.get("account_name"),
        }
        # Include subtransactions if this is a split
        subtxns = t.get("subtransactions", [])
        if subtxns:
            txn["subtransactions"] = [
                {
                    "id": s.get("id"),
                    "amount": s.get("amount"),
                    "amount_display": _format_milliunits(s.get("amount")),
                    "payee_name": s.get("payee_name"),
                    "category_name": s.get("category_name"),
                    "memo": s.get("memo"),
                }
                for s in subtxns
            ]
        transactions.append(txn)

    return json.dumps({
        "success": True,
        "count": len(transactions),
        "total_available": total_available,
        "truncated": total_available > len(transactions),
        "transactions": transactions,
        "server_knowledge": result.get("data", {}).get("server_knowledge"),
    }, indent=2)


@mcp.tool()
def create_transaction(
    account_id: str,
    date: str,
    amount: int,
    payee_name: Optional[str] = None,
    payee_id: Optional[str] = None,
    category_id: Optional[str] = None,
    memo: Optional[str] = None,
    cleared: str = "cleared",
    approved: bool = True,
    flag_color: Optional[str] = None,
    subtransactions: Optional[list] = None,
    budget_id: Optional[str] = None,
) -> str:
    """Create a new transaction.

    Args:
        account_id: The account UUID to create the transaction in.
        date: Transaction date in YYYY-MM-DD format.
        amount: Amount in milliunits (negative for outflows, positive for inflows).
                Example: -50000 = -$50.00 outflow, 150000 = $150.00 inflow.
        payee_name: Name of payee (creates new payee if doesn't exist). Use this OR payee_id.
        payee_id: UUID of existing payee. Use this OR payee_name.
        category_id: UUID of the budget category. Omit when using subtransactions (each sub has its own).
        memo: Transaction memo.
        cleared: Cleared status: "cleared", "uncleared", or "reconciled". Defaults to "cleared".
        approved: Whether the transaction is approved. Defaults to True.
        flag_color: Optional flag: red, orange, yellow, green, blue, purple.
        subtransactions: Array of subtransaction objects for split transactions.
                Each item: {"amount": int, "category_id": "uuid", "memo": "text", "payee_id": "uuid", "payee_name": "text"}.
                Only amount and category_id are required per sub. The sub amounts must sum to the parent amount.
                When using subtransactions, omit category_id on the parent (it becomes a split).
        budget_id: Budget ID (uses default if omitted).

    Returns:
        Created transaction details with id, date, amount, payee, category, and subtransactions.
    """
    _require_config()
    _validate_cleared(cleared)
    _validate_flag_color(flag_color)
    bid = _resolve_budget_id(budget_id)

    txn = {
        "account_id": account_id,
        "date": date,
        "amount": amount,
        "cleared": cleared,
        "approved": approved,
    }
    if payee_name:
        txn["payee_name"] = payee_name
    if payee_id:
        txn["payee_id"] = payee_id
    if category_id:
        txn["category_id"] = category_id
    if memo:
        txn["memo"] = memo
    if flag_color:
        txn["flag_color"] = flag_color

    if subtransactions:
        sub_total = sum(s.get("amount", 0) for s in subtransactions)
        if sub_total != amount:
            return json.dumps({
                "success": False,
                "error": f"Subtransaction amounts ({sub_total}) must sum to parent amount ({amount}).",
            })
        txn["subtransactions"] = subtransactions

    result = _api_request(f"/budgets/{bid}/transactions", method="POST", body={"transaction": txn})
    t = result.get("data", {}).get("transaction", {})

    response = {
        "success": True,
        "id": t.get("id"),
        "date": t.get("date"),
        "amount": t.get("amount"),
        "amount_display": _format_milliunits(t.get("amount")),
        "payee_name": t.get("payee_name"),
        "category_name": t.get("category_name"),
        "account_name": t.get("account_name"),
        "cleared": t.get("cleared"),
        "approved": t.get("approved"),
        "memo": t.get("memo"),
    }
    subtxns = t.get("subtransactions", [])
    if subtxns:
        response["subtransactions"] = [
            {
                "id": s.get("id"),
                "amount": s.get("amount"),
                "amount_display": _format_milliunits(s.get("amount")),
                "payee_name": s.get("payee_name"),
                "category_name": s.get("category_name"),
                "memo": s.get("memo"),
            }
            for s in subtxns
        ]
    return json.dumps(response, indent=2)


@mcp.tool()
def update_month_category(
    category_id: str,
    budgeted: int,
    month: Optional[str] = None,
    budget_id: Optional[str] = None,
) -> str:
    """Update the budgeted amount for a category in a specific month.

    Use this to move money between categories or adjust budget allocations.

    Args:
        category_id: The category UUID to update.
        budgeted: New budgeted amount in milliunits (e.g., 50000 = $50.00).
        month: Month in YYYY-MM-DD format (first of month). Defaults to current month.
        budget_id: Budget ID (uses default if omitted).

    Returns:
        Updated category with new budgeted amount, activity, and balance.
    """
    _require_config()
    bid = _resolve_budget_id(budget_id)
    m = month or _current_month()

    result = _api_request(
        f"/budgets/{bid}/months/{m}/categories/{category_id}",
        method="PATCH",
        body={"category": {"budgeted": budgeted}},
    )
    c = result.get("data", {}).get("category", {})

    return json.dumps({
        "success": True,
        "id": c.get("id"),
        "name": c.get("name"),
        "budgeted": c.get("budgeted"),
        "budgeted_display": _format_milliunits(c.get("budgeted")),
        "activity": c.get("activity"),
        "activity_display": _format_milliunits(c.get("activity")),
        "balance": c.get("balance"),
        "balance_display": _format_milliunits(c.get("balance")),
    }, indent=2)


# ---------------------------------------------------------------------------
# Tools — Extended
# ---------------------------------------------------------------------------


@mcp.tool()
def update_transaction(
    transaction_id: str,
    account_id: Optional[str] = None,
    date: Optional[str] = None,
    amount: Optional[int] = None,
    payee_name: Optional[str] = None,
    payee_id: Optional[str] = None,
    category_id: Optional[str] = None,
    memo: Optional[str] = None,
    cleared: Optional[str] = None,
    approved: Optional[bool] = None,
    flag_color: Optional[str] = None,
    subtransactions: Optional[list] = None,
    budget_id: Optional[str] = None,
) -> str:
    """Update an existing transaction.

    Args:
        transaction_id: The transaction UUID to update.
        account_id: Move to a different account.
        date: New date (YYYY-MM-DD).
        amount: New amount in milliunits.
        payee_name: New payee name.
        payee_id: New payee UUID.
        category_id: New category UUID.
        memo: New memo.
        cleared: New cleared status: "cleared", "uncleared", or "reconciled".
        approved: New approved status.
        flag_color: New flag color: red, orange, yellow, green, blue, purple.
        subtransactions: Array of subtransaction objects to convert this into a split transaction.
                Each item: {"amount": int, "category_id": "uuid", "memo": "text", "payee_id": "uuid", "payee_name": "text"}.
                Only amount and category_id are required per sub. The sub amounts must sum to the parent amount.
                When adding subtransactions, also provide the new parent amount if changing it.
        budget_id: Budget ID (uses default if omitted).

    Returns:
        Updated transaction details.
    """
    _require_config()
    _validate_cleared(cleared)
    _validate_flag_color(flag_color)
    bid = _resolve_budget_id(budget_id)

    txn: dict = {}
    if account_id is not None:
        txn["account_id"] = account_id
    if date is not None:
        txn["date"] = date
    if amount is not None:
        txn["amount"] = amount
    if payee_name is not None:
        txn["payee_name"] = payee_name
    if payee_id is not None:
        txn["payee_id"] = payee_id
    if category_id is not None:
        txn["category_id"] = category_id
    if memo is not None:
        txn["memo"] = memo
    if cleared is not None:
        txn["cleared"] = cleared
    if approved is not None:
        txn["approved"] = approved
    if flag_color is not None:
        txn["flag_color"] = flag_color

    if subtransactions is not None:
        txn["subtransactions"] = subtransactions

    if not txn:
        return json.dumps({"success": False, "error": "No fields to update. Provide at least one field."})

    result = _api_request(
        f"/budgets/{bid}/transactions/{transaction_id}",
        method="PUT",
        body={"transaction": txn},
    )
    t = result.get("data", {}).get("transaction", {})

    response = {
        "success": True,
        "id": t.get("id"),
        "date": t.get("date"),
        "amount": t.get("amount"),
        "amount_display": _format_milliunits(t.get("amount")),
        "payee_name": t.get("payee_name"),
        "category_name": t.get("category_name"),
        "account_name": t.get("account_name"),
        "cleared": t.get("cleared"),
        "approved": t.get("approved"),
        "memo": t.get("memo"),
    }
    subtxns = t.get("subtransactions", [])
    if subtxns:
        response["subtransactions"] = [
            {
                "id": s.get("id"),
                "amount": s.get("amount"),
                "amount_display": _format_milliunits(s.get("amount")),
                "payee_name": s.get("payee_name"),
                "category_name": s.get("category_name"),
                "memo": s.get("memo"),
            }
            for s in subtxns
        ]
    return json.dumps(response, indent=2)


@mcp.tool()
def delete_transaction(
    transaction_id: str,
    budget_id: Optional[str] = None,
) -> str:
    """Delete a transaction.

    Args:
        transaction_id: The transaction UUID to delete.
        budget_id: Budget ID (uses default if omitted).

    Returns:
        Confirmation of deletion.
    """
    _require_config()
    bid = _resolve_budget_id(budget_id)

    result = _api_request(
        f"/budgets/{bid}/transactions/{transaction_id}",
        method="DELETE",
    )
    t = result.get("data", {}).get("transaction", {})

    return json.dumps({
        "success": True,
        "id": t.get("id"),
        "deleted": True,
    }, indent=2)


@mcp.tool()
def create_transactions_bulk(
    transactions_json: str,
    budget_id: Optional[str] = None,
) -> str:
    """Create multiple transactions at once from a JSON string.

    The JSON should contain a "transactions" array where each item has:
    account_id (required), date (required), amount (required in milliunits),
    and optionally: payee_name, payee_id, category_id, memo, cleared, approved, flag_color,
    subtransactions (array of {amount, category_id, memo, payee_id, payee_name}).

    Args:
        transactions_json: JSON string with a "transactions" array.
        budget_id: Budget ID (uses default if omitted).

    Returns:
        Summary of created and duplicate transactions.
    """
    _require_config()
    bid = _resolve_budget_id(budget_id)

    try:
        data = json.loads(transactions_json)
    except json.JSONDecodeError as e:
        return json.dumps({"success": False, "error": f"Invalid JSON: {e}"})

    txns = data.get("transactions", [])
    if not txns:
        return json.dumps({"success": False, "error": "No 'transactions' array found in JSON."})

    # Validate each transaction
    for i, txn in enumerate(txns):
        if not txn.get("account_id"):
            return json.dumps({"success": False, "error": f"Transaction {i}: missing account_id."})
        if not txn.get("date"):
            return json.dumps({"success": False, "error": f"Transaction {i}: missing date."})
        if txn.get("amount") is None:
            return json.dumps({"success": False, "error": f"Transaction {i}: missing amount."})
        _validate_cleared(txn.get("cleared"))
        _validate_flag_color(txn.get("flag_color"))

    result = _api_request(
        f"/budgets/{bid}/transactions",
        method="POST",
        body={"transactions": txns},
    )
    bulk_data = result.get("data", {})

    created_ids = bulk_data.get("transaction_ids", [])
    duplicate_ids = bulk_data.get("duplicate_import_ids", [])

    return json.dumps({
        "success": True,
        "created_count": len(created_ids),
        "duplicate_count": len(duplicate_ids),
        "transaction_ids": created_ids,
        "duplicate_import_ids": duplicate_ids,
    }, indent=2)


@mcp.tool()
def get_scheduled_transactions(
    budget_id: Optional[str] = None,
) -> str:
    """List all scheduled (recurring) transactions.

    Args:
        budget_id: Budget ID (uses default if omitted).

    Returns:
        List of scheduled transactions with frequency, next date, amount, payee, category.
    """
    _require_config()
    bid = _resolve_budget_id(budget_id)

    result = _api_request(f"/budgets/{bid}/scheduled_transactions")
    txns_data = result.get("data", {}).get("scheduled_transactions", [])

    transactions = []
    for t in txns_data:
        if t.get("deleted"):
            continue
        txn = {
            "id": t.get("id"),
            "date_first": t.get("date_first"),
            "date_next": t.get("date_next"),
            "frequency": t.get("frequency"),
            "amount": t.get("amount"),
            "amount_display": _format_milliunits(t.get("amount")),
            "payee_name": t.get("payee_name"),
            "category_name": t.get("category_name"),
            "account_name": t.get("account_name"),
            "memo": t.get("memo"),
            "flag_color": t.get("flag_color"),
        }
        subtxns = t.get("subtransactions", [])
        if subtxns:
            txn["subtransactions"] = [
                {
                    "id": s.get("id"),
                    "amount": s.get("amount"),
                    "amount_display": _format_milliunits(s.get("amount")),
                    "payee_name": s.get("payee_name"),
                    "category_name": s.get("category_name"),
                    "memo": s.get("memo"),
                }
                for s in subtxns
            ]
        transactions.append(txn)

    return json.dumps({
        "success": True,
        "count": len(transactions),
        "scheduled_transactions": transactions,
    }, indent=2)


@mcp.tool()
def create_account(
    name: str,
    type: str,
    balance: int,
    budget_id: Optional[str] = None,
) -> str:
    """Create a new account in a budget.

    Args:
        name: Account name (e.g., "Chase Checking").
        type: Account type. One of: checking, savings, cash, creditCard, lineOfCredit,
              otherAsset, otherLiability, mortgage, autoLoan, studentLoan, personalLoan,
              medicalDebt, otherDebt.
        balance: Starting balance in milliunits (e.g., 100000 = $100.00).
        budget_id: Budget ID (uses default if omitted).

    Returns:
        Created account details with id, name, type, and balance.
    """
    _require_config()
    _validate_account_type(type)
    bid = _resolve_budget_id(budget_id)

    result = _api_request(
        f"/budgets/{bid}/accounts",
        method="POST",
        body={
            "account": {
                "name": name,
                "type": type,
                "balance": balance,
            }
        },
    )
    a = result.get("data", {}).get("account", {})

    return json.dumps({
        "success": True,
        "id": a.get("id"),
        "name": a.get("name"),
        "type": a.get("type"),
        "on_budget": a.get("on_budget"),
        "balance": a.get("balance"),
        "balance_display": _format_milliunits(a.get("balance")),
    }, indent=2)


@mcp.tool()
def get_budget_months(
    budget_id: Optional[str] = None,
) -> str:
    """List all months in a budget with summary data.

    Useful for trend analysis — see how income, spending, and budgeting
    have changed over time.

    Args:
        budget_id: Budget ID (uses default if omitted).

    Returns:
        List of months with income, budgeted, activity, to_be_budgeted, age_of_money.
    """
    _require_config()
    bid = _resolve_budget_id(budget_id)

    result = _api_request(f"/budgets/{bid}/months")
    months_data = result.get("data", {}).get("months", [])

    months = []
    for m in months_data:
        months.append({
            "month": m.get("month"),
            "income": m.get("income"),
            "income_display": _format_milliunits(m.get("income")),
            "budgeted": m.get("budgeted"),
            "budgeted_display": _format_milliunits(m.get("budgeted")),
            "activity": m.get("activity"),
            "activity_display": _format_milliunits(m.get("activity")),
            "to_be_budgeted": m.get("to_be_budgeted"),
            "to_be_budgeted_display": _format_milliunits(m.get("to_be_budgeted")),
            "age_of_money": m.get("age_of_money"),
        })

    return json.dumps({
        "success": True,
        "count": len(months),
        "months": months,
    }, indent=2)


@mcp.tool()
def update_category(
    category_id: str,
    name: Optional[str] = None,
    note: Optional[str] = None,
    goal_target: Optional[int] = None,
    budget_id: Optional[str] = None,
) -> str:
    """Update a category's name, note, or goal target.

    Args:
        category_id: The category UUID.
        name: New category name.
        note: New category note.
        goal_target: New goal target in milliunits (e.g., 500000 = $500.00).
        budget_id: Budget ID (uses default if omitted).

    Returns:
        Updated category details.
    """
    _require_config()
    bid = _resolve_budget_id(budget_id)

    cat: dict = {}
    if name is not None:
        cat["name"] = name
    if note is not None:
        cat["note"] = note
    if goal_target is not None:
        cat["goal_target"] = goal_target

    if not cat:
        return json.dumps({"success": False, "error": "No fields to update. Provide at least one field."})

    result = _api_request(
        f"/budgets/{bid}/categories/{category_id}",
        method="PATCH",
        body={"category": cat},
    )
    c = result.get("data", {}).get("category", {})

    return json.dumps({
        "success": True,
        "id": c.get("id"),
        "name": c.get("name"),
        "note": c.get("note"),
        "budgeted": c.get("budgeted"),
        "budgeted_display": _format_milliunits(c.get("budgeted")),
        "balance": c.get("balance"),
        "balance_display": _format_milliunits(c.get("balance")),
        "goal_type": c.get("goal_type"),
        "goal_target": c.get("goal_target"),
        "goal_target_display": _format_milliunits(c.get("goal_target")),
    }, indent=2)


# ---------------------------------------------------------------------------
# Multi-User URL Routing Middleware
# ---------------------------------------------------------------------------

_USER_PATH_PATTERN = re.compile(r"^/([a-z0-9_]+)/mcp(/.*)?$", re.IGNORECASE)


class MultiUserMiddleware:
    """ASGI middleware that routes /<username>/mcp to the MCP app with per-user token.

    URL routing:
        /adam/mcp   → sets token from YNAB_TOKEN_ADAM, rewrites path to /mcp
        /sarah/mcp  → sets token from YNAB_TOKEN_SARAH, rewrites path to /mcp
        /mcp        → uses default YNAB_ACCESS_TOKEN
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        match = _USER_PATH_PATTERN.match(path)

        if match:
            username = match.group(1).lower()
            remainder = match.group(2) or ""

            token = USER_TOKENS.get(username)
            if not token:
                await send({
                    "type": "http.response.start",
                    "status": 404,
                    "headers": [(b"content-type", b"application/json")],
                })
                await send({
                    "type": "http.response.body",
                    "body": json.dumps({
                        "error": "Not found"
                    }).encode(),
                })
                return

            _current_token.set(token)
            scope = dict(scope)
            scope["path"] = f"/mcp{remainder}"
            logger.debug("Routing request for user '%s' to /mcp%s", username, remainder)
        else:
            _current_token.set(DEFAULT_TOKEN)

        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="YNAB MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="Transport to use (default: stdio)",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (HTTP transport only)")
    default_port = int(os.environ.get("PORT", "8000"))
    parser.add_argument("--port", type=int, default=default_port, help="Port to bind to (HTTP transport only)")
    args = parser.parse_args()

    if args.transport == "streamable-http":
        app = MultiUserMiddleware(mcp.streamable_http_app())
        logger.info("Starting YNAB MCP server on %s:%d", args.host, args.port)
        if USER_TOKENS:
            logger.info("User endpoints: %s", ", ".join(f"/{u}/mcp" for u in sorted(USER_TOKENS)))
        uvicorn.run(app, host=args.host, port=args.port)
    else:
        _current_token.set(DEFAULT_TOKEN)
        mcp.run(transport="stdio")
