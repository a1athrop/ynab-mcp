# YNAB MCP Server

MCP server for [YNAB (You Need A Budget)](https://www.ynab.com/) — manage budgets, accounts, categories, and transactions through Claude.

## Tools

### Core (daily budget management)
| Tool | Description |
|------|-------------|
| `get_budgets` | List all budgets |
| `get_accounts` | List accounts with balances |
| `get_categories` | Category groups with budgeted/activity/balance |
| `get_payees` | List payees (for resolving names to IDs) |
| `get_month` | Monthly overview with per-category breakdown |
| `get_transactions` | Search transactions by date/account/category/payee |
| `create_transaction` | Add a new transaction |
| `update_month_category` | Change budgeted amount for a category |

### Extended (weekly/occasional)
| Tool | Description |
|------|-------------|
| `update_transaction` | Edit existing transaction fields |
| `delete_transaction` | Delete a transaction |
| `create_transactions_bulk` | Create multiple transactions from JSON |
| `get_scheduled_transactions` | View recurring/upcoming bills |
| `create_account` | Add a new account |
| `get_budget_months` | Historical month list for trends |
| `update_category` | Change category name, note, or goal |

## Setup

### 1. Get a YNAB Personal Access Token

Go to [YNAB Settings > Developer Settings](https://app.ynab.com/settings) and create a Personal Access Token.

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and set YNAB_ACCESS_TOKEN
```

### 3. Run locally

```bash
# stdio transport (Claude Desktop / Claude Code)
uv run server.py

# HTTP transport (Claude.ai connector / remote access)
uv run server.py --transport streamable-http
```

### 4. Claude Desktop configuration

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ynab": {
      "command": "uv",
      "args": ["run", "/path/to/ynab-mcp/server.py"],
      "env": {
        "YNAB_ACCESS_TOKEN": "your-token-here"
      }
    }
  }
}
```

## Deployment (Railway)

1. Push this repo to GitHub
2. Create a new Railway project and connect the repo
3. Set environment variables in Railway:
   - `YNAB_ACCESS_TOKEN` — your YNAB Personal Access Token
   - `YNAB_DEFAULT_BUDGET_ID` — (optional) default budget UUID or "last-used"
   - `MCP_BEARER_TOKEN` — (optional) secure the MCP endpoint
4. Railway auto-deploys on push to `main`

The server reads the `PORT` environment variable (set automatically by Railway).

## Multi-User Support

Set per-user tokens to give each person their own connector URL:

```bash
YNAB_TOKEN_ADAM=adams-token
YNAB_TOKEN_SARAH=sarahs-token
```

URL routing:
- `/adam/mcp` — uses `YNAB_TOKEN_ADAM`
- `/sarah/mcp` — uses `YNAB_TOKEN_SARAH`
- `/mcp` — uses `YNAB_ACCESS_TOKEN` (default)

## Currency Format

YNAB uses **milliunits** (1/1000 of a currency unit):
- `$10.00` = `10000` milliunits
- `-$5.50` = `-5500` milliunits

All tool responses include both raw milliunit values and formatted display strings (e.g., `balance` and `balance_display`).

## Rate Limits

YNAB allows **200 requests per hour** per access token. The server returns friendly error messages when rate limited (HTTP 429).
