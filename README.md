# Strong Password Generator MCP

A Model Context Protocol (MCP) server for generating cryptographically secure, customizable passwords. Built with FastMCP 2.0.

## Features

- **Cryptographically secure** - Uses Python's `secrets` module
- **Customizable length** - 8 to 128 characters
- **Character options** - Symbols, numbers, mixed/upper/lowercase
- **Exclude ambiguous characters** - Remove confusing chars like `0`, `O`, `l`, `1`, `I`
- **Strength analysis** - Entropy calculation and security rating
- **Passphrase generation** - Word-based memorable passwords

## Tools

| Tool | Description |
|------|-------------|
| `generate_password` | Generate a single password with full customization |
| `generate_multiple_passwords` | Generate 1-20 passwords at once |
| `check_password_strength` | Analyze the security of any password |
| `generate_passphrase` | Create memorable word-based passphrases |

## Installation for Claude Desktop

### Step 1: Install uv (if not installed)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Step 2: Clone and sync dependencies

```bash
git clone https://github.com/alfredang/strong-password-generator.git
cd strong-password-generator
uv sync
```

### Step 3: Configure Claude Desktop

Open the Claude Desktop config file:

**macOS:**
```bash
code ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

Add this MCP server configuration:

```json
{
  "mcpServers": {
    "password-generator": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/strong-password-generator",
        "run",
        "python",
        "server.py"
      ]
    }
  }
}
```

> **Note:** Replace `/path/to/strong-password-generator` with the actual path where you cloned the repo.

### Step 4: Restart Claude Desktop

Completely quit Claude Desktop and reopen it. The password generator tools will now be available.

### Step 5: Verify Installation

In Claude Desktop, you can ask:

- "Generate a strong 20-character password"
- "Create 5 passwords without symbols"
- "Check the strength of my password: abc123"
- "Generate a memorable passphrase"

### Testing with MCP Inspector (Optional)

```bash
npx @modelcontextprotocol/inspector uv --directory /path/to/strong-password-generator run python server.py
```

This opens a web UI to test tools interactively.

## Usage Examples

Once installed, you can ask Claude:

- "Generate a strong 24-character password"
- "Create 5 passwords without symbols"
- "Check the strength of this password: MyP@ssw0rd!"
- "Generate a memorable passphrase with 5 words"

### Tool Parameters

#### generate_password

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `length` | int | 16 | Password length (8-128) |
| `include_symbols` | bool | true | Include `!@#$%^&*()` etc. |
| `include_numbers` | bool | true | Include digits 0-9 |
| `case` | string | "mixed" | "mixed", "uppercase", or "lowercase" |
| `exclude_ambiguous` | bool | false | Remove `0`, `O`, `l`, `1`, `I` |
| `custom_symbols` | string | null | Custom symbol set to use |

## License

MIT
