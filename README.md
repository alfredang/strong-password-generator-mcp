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

## Installation

### Prerequisites

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) package manager

### Setup

```bash
git clone https://github.com/alfredang/strong-password-generator.git
cd strong-password-generator
uv sync
```

### Configure Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

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

Restart Claude Desktop to load the server.

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

## Testing

Test with MCP Inspector:

```bash
npx @modelcontextprotocol/inspector uv --directory . run python server.py
```

## License

MIT
