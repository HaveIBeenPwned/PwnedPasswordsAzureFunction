# Security Notice

This document outlines general security procedures and policies for Pwned Passwords Azure Function

## Reporting a vulnerability 

Please report security vulnerabilities to Troy Hunt via [email](mailto:security@troyhunt.com) to work on verifying the vulnerability and fixing it. You will receive a response within 48 hours. Please allow the vulnerability to be fixed before any public exposure, as this will help protect all of the people who use the Pwned Passwords service. 

Within the report of the issue, please provide the following information:

- History of how long the vulnerability existed in the project (e.g. commit version)
- Component(s) affected
- A description of the vulnerability, the impact, and how to reproduce it
- Recommended remediations
- (Optional) Code, screenshots, or videos of the vulnerability (but no executable binaries)

For sensitive communications, you can use [Keybase](https://keybase.io/troyhunt).

## Scope

The following items are **not** in scope:
- High volume vulnerabilities, such as overwhelming the service with requests, Dos, brute force attacks, etc.
- Rate limitations or service limitations, unless it allows bypassing of rate-limits, API keys, or other security measures
- Vulnerabilities from old versions of the project