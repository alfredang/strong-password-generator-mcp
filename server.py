#!/usr/bin/env python3
"""
Password Generator MCP Server.

This server provides tools to generate strong, customizable passwords
with various character sets and complexity options.
"""

import secrets
import string
import json
from typing import Optional
from enum import Enum
from pydantic import BaseModel, Field, field_validator, ConfigDict
from mcp.server.fastmcp import FastMCP

# Initialize the MCP server
mcp = FastMCP("password_generator_mcp")


class CaseOption(str, Enum):
    """Case options for password generation."""
    MIXED = "mixed"       # Both uppercase and lowercase
    UPPERCASE = "uppercase"  # Only uppercase letters
    LOWERCASE = "lowercase"  # Only lowercase letters


class GeneratePasswordInput(BaseModel):
    """Input model for password generation."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    length: int = Field(
        default=16,
        description="Number of characters in the password (8-128)",
        ge=8,
        le=128
    )
    include_symbols: bool = Field(
        default=True,
        description="Include special symbols (!@#$%^&*()-_=+[]{}|;:,.<>?)"
    )
    include_numbers: bool = Field(
        default=True,
        description="Include numeric digits (0-9)"
    )
    case: CaseOption = Field(
        default=CaseOption.MIXED,
        description="Letter case: 'mixed' (upper+lower), 'uppercase', or 'lowercase'"
    )
    exclude_ambiguous: bool = Field(
        default=False,
        description="Exclude ambiguous characters (0, O, l, 1, I) for better readability"
    )
    custom_symbols: Optional[str] = Field(
        default=None,
        description="Custom set of symbols to use instead of default (e.g., '!@#$')",
        max_length=50
    )

    @field_validator('length')
    @classmethod
    def validate_length(cls, v: int) -> int:
        if v < 8:
            raise ValueError("Password length must be at least 8 characters for security")
        if v > 128:
            raise ValueError("Password length cannot exceed 128 characters")
        return v


class GenerateMultipleInput(BaseModel):
    """Input model for generating multiple passwords."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    count: int = Field(
        default=5,
        description="Number of passwords to generate (1-20)",
        ge=1,
        le=20
    )
    length: int = Field(
        default=16,
        description="Number of characters in each password (8-128)",
        ge=8,
        le=128
    )
    include_symbols: bool = Field(
        default=True,
        description="Include special symbols"
    )
    include_numbers: bool = Field(
        default=True,
        description="Include numeric digits"
    )
    case: CaseOption = Field(
        default=CaseOption.MIXED,
        description="Letter case option"
    )
    exclude_ambiguous: bool = Field(
        default=False,
        description="Exclude ambiguous characters"
    )


class CheckStrengthInput(BaseModel):
    """Input model for password strength checking."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    password: str = Field(
        ...,
        description="The password to analyze",
        min_length=1,
        max_length=256
    )


def _build_charset(
    include_symbols: bool,
    include_numbers: bool,
    case: CaseOption,
    exclude_ambiguous: bool,
    custom_symbols: Optional[str] = None
) -> str:
    """Build the character set based on options."""
    charset = ""

    # Add letters based on case option
    if case == CaseOption.MIXED:
        charset += string.ascii_lowercase + string.ascii_uppercase
    elif case == CaseOption.UPPERCASE:
        charset += string.ascii_uppercase
    elif case == CaseOption.LOWERCASE:
        charset += string.ascii_lowercase

    # Add numbers
    if include_numbers:
        charset += string.digits

    # Add symbols
    if include_symbols:
        if custom_symbols:
            charset += custom_symbols
        else:
            charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    # Remove ambiguous characters if requested
    if exclude_ambiguous:
        ambiguous = "0O1lI"
        charset = "".join(c for c in charset if c not in ambiguous)

    return charset


def _generate_password(
    length: int,
    include_symbols: bool,
    include_numbers: bool,
    case: CaseOption,
    exclude_ambiguous: bool,
    custom_symbols: Optional[str] = None
) -> str:
    """Generate a single password with the given options."""
    charset = _build_charset(
        include_symbols=include_symbols,
        include_numbers=include_numbers,
        case=case,
        exclude_ambiguous=exclude_ambiguous,
        custom_symbols=custom_symbols
    )

    if not charset:
        raise ValueError("No characters available with the given options")

    # Generate password using cryptographically secure random
    password = "".join(secrets.choice(charset) for _ in range(length))

    return password


def _calculate_entropy(password: str) -> float:
    """Calculate the entropy of a password in bits."""
    import math

    charset_size = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 32  # Approximate number of common symbols

    if charset_size == 0:
        return 0.0

    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)


def _get_strength_rating(entropy: float) -> tuple[str, str]:
    """Get strength rating and description based on entropy."""
    if entropy < 28:
        return "Very Weak", "Easily cracked in seconds"
    elif entropy < 36:
        return "Weak", "Can be cracked in minutes to hours"
    elif entropy < 60:
        return "Moderate", "May take days to months to crack"
    elif entropy < 80:
        return "Strong", "Would take years to crack"
    elif entropy < 100:
        return "Very Strong", "Would take centuries to crack"
    else:
        return "Excellent", "Practically uncrackable with current technology"


@mcp.tool(
    name="generate_password",
    annotations={
        "title": "Generate Strong Password",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False
    }
)
async def generate_password(params: GeneratePasswordInput) -> str:
    """Generate a cryptographically secure password with customizable options.

    This tool creates strong passwords using Python's secrets module for
    cryptographic randomness. You can customize length, character sets,
    and various options to meet different password requirements.

    Args:
        params (GeneratePasswordInput): Password generation options:
            - length (int): Password length, 8-128 characters (default: 16)
            - include_symbols (bool): Include !@#$%^&* etc. (default: True)
            - include_numbers (bool): Include 0-9 (default: True)
            - case (str): 'mixed', 'uppercase', or 'lowercase' (default: 'mixed')
            - exclude_ambiguous (bool): Remove 0, O, l, 1, I (default: False)
            - custom_symbols (str): Custom symbol set to use (optional)

    Returns:
        str: JSON containing the generated password and its properties

    Examples:
        - Default strong password: {} -> 16 char with symbols, numbers, mixed case
        - Simple alphanumeric: {"include_symbols": false} -> letters and numbers only
        - Extra long: {"length": 32} -> 32 character password
        - Readable: {"exclude_ambiguous": true} -> no confusing characters
    """
    try:
        password = _generate_password(
            length=params.length,
            include_symbols=params.include_symbols,
            include_numbers=params.include_numbers,
            case=params.case,
            exclude_ambiguous=params.exclude_ambiguous,
            custom_symbols=params.custom_symbols
        )

        entropy = _calculate_entropy(password)
        strength, description = _get_strength_rating(entropy)

        result = {
            "password": password,
            "length": len(password),
            "entropy_bits": entropy,
            "strength": strength,
            "strength_description": description,
            "options_used": {
                "symbols": params.include_symbols,
                "numbers": params.include_numbers,
                "case": params.case.value,
                "exclude_ambiguous": params.exclude_ambiguous
            }
        }

        return json.dumps(result, indent=2)

    except ValueError as e:
        return json.dumps({"error": str(e)})


@mcp.tool(
    name="generate_multiple_passwords",
    annotations={
        "title": "Generate Multiple Passwords",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False
    }
)
async def generate_multiple_passwords(params: GenerateMultipleInput) -> str:
    """Generate multiple unique passwords at once.

    Useful when you need several passwords, such as for different accounts
    or to provide options to choose from.

    Args:
        params (GenerateMultipleInput): Generation options:
            - count (int): Number of passwords to generate, 1-20 (default: 5)
            - length (int): Length of each password, 8-128 (default: 16)
            - include_symbols (bool): Include symbols (default: True)
            - include_numbers (bool): Include numbers (default: True)
            - case (str): Case option (default: 'mixed')
            - exclude_ambiguous (bool): Exclude confusing chars (default: False)

    Returns:
        str: JSON array of generated passwords with their properties
    """
    try:
        passwords = []
        for i in range(params.count):
            password = _generate_password(
                length=params.length,
                include_symbols=params.include_symbols,
                include_numbers=params.include_numbers,
                case=params.case,
                exclude_ambiguous=params.exclude_ambiguous
            )
            entropy = _calculate_entropy(password)
            strength, _ = _get_strength_rating(entropy)

            passwords.append({
                "index": i + 1,
                "password": password,
                "entropy_bits": entropy,
                "strength": strength
            })

        result = {
            "count": len(passwords),
            "passwords": passwords,
            "options_used": {
                "length": params.length,
                "symbols": params.include_symbols,
                "numbers": params.include_numbers,
                "case": params.case.value,
                "exclude_ambiguous": params.exclude_ambiguous
            }
        }

        return json.dumps(result, indent=2)

    except ValueError as e:
        return json.dumps({"error": str(e)})


@mcp.tool(
    name="check_password_strength",
    annotations={
        "title": "Check Password Strength",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def check_password_strength(params: CheckStrengthInput) -> str:
    """Analyze the strength of a given password.

    Evaluates a password's security by checking character diversity,
    length, and calculating entropy. Provides a strength rating and
    recommendations for improvement.

    Args:
        params (CheckStrengthInput): Input containing:
            - password (str): The password to analyze

    Returns:
        str: JSON with strength analysis including entropy, rating, and tips
    """
    password = params.password

    # Character analysis
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    # Calculate entropy
    entropy = _calculate_entropy(password)
    strength, description = _get_strength_rating(entropy)

    # Generate recommendations
    recommendations = []
    if len(password) < 12:
        recommendations.append("Increase length to at least 12 characters")
    if len(password) < 16:
        recommendations.append("Consider using 16+ characters for better security")
    if not has_lower:
        recommendations.append("Add lowercase letters")
    if not has_upper:
        recommendations.append("Add uppercase letters")
    if not has_digit:
        recommendations.append("Add numbers")
    if not has_symbol:
        recommendations.append("Add special symbols")

    result = {
        "length": len(password),
        "entropy_bits": entropy,
        "strength": strength,
        "strength_description": description,
        "character_analysis": {
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_numbers": has_digit,
            "has_symbols": has_symbol,
            "unique_characters": len(set(password))
        },
        "recommendations": recommendations if recommendations else ["Password meets strong security criteria"]
    }

    return json.dumps(result, indent=2)


@mcp.tool(
    name="generate_passphrase",
    annotations={
        "title": "Generate Passphrase",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False
    }
)
async def generate_passphrase(
    word_count: int = Field(default=4, description="Number of words (3-8)", ge=3, le=8),
    separator: str = Field(default="-", description="Character between words", max_length=3),
    capitalize: bool = Field(default=True, description="Capitalize first letter of each word"),
    include_number: bool = Field(default=True, description="Append a random number")
) -> str:
    """Generate a memorable passphrase using random words.

    Creates an easy-to-remember passphrase using random common words.
    Passphrases are often easier to type and remember while still
    being secure due to their length.

    Args:
        word_count: Number of words (3-8, default: 4)
        separator: Separator between words (default: "-")
        capitalize: Capitalize each word (default: True)
        include_number: Add random number at end (default: True)

    Returns:
        str: JSON with the passphrase and its properties
    """
    # Common words list (subset for demonstration - in production use a larger wordlist)
    words = [
        "apple", "banana", "cherry", "dragon", "eagle", "forest", "galaxy", "harbor",
        "island", "jungle", "kitten", "lemon", "mountain", "nebula", "ocean", "planet",
        "quantum", "river", "sunset", "thunder", "umbrella", "valley", "whisper", "xylophone",
        "yellow", "zebra", "anchor", "bridge", "castle", "diamond", "ember", "falcon",
        "glacier", "horizon", "ivory", "jasmine", "kingdom", "lantern", "meadow", "ninja",
        "orchid", "phoenix", "quartz", "rainbow", "silver", "tiger", "unity", "violet",
        "winter", "xenon", "yarn", "zephyr", "aurora", "breeze", "crystal", "dusk"
    ]

    # Select random words
    selected = [secrets.choice(words) for _ in range(word_count)]

    # Apply capitalization
    if capitalize:
        selected = [word.capitalize() for word in selected]

    # Build passphrase
    passphrase = separator.join(selected)

    # Add number if requested
    if include_number:
        passphrase += separator + str(secrets.randbelow(1000))

    # Calculate entropy (rough estimate)
    entropy = _calculate_entropy(passphrase)
    strength, description = _get_strength_rating(entropy)

    result = {
        "passphrase": passphrase,
        "word_count": word_count,
        "total_length": len(passphrase),
        "entropy_bits": entropy,
        "strength": strength,
        "strength_description": description
    }

    return json.dumps(result, indent=2)


if __name__ == "__main__":
    mcp.run()
