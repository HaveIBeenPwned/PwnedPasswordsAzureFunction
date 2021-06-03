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

## Communication

GitHub Security Advisory will be used to communicate during the process of identifying, fixing and shipping the mitigation of the vulnerability.

The advisory will only be made public when the patched version is released to inform the community of the breach and its potential security impact.

## Scope

The following items are **not** in scope:
- High volume vulnerabilities, such as overwhelming the service with requests, Dos, brute force attacks, etc.
- Rate limitations or service limitations, unless it allows bypassing of rate-limits, API keys, or other security measures
- Vulnerabilities from old versions of the project

## Compensation

We do not provide compensation for reporting vulnerabilities, except for eternal gratitude for helping keep Pwned Passwords a secure and reliable service.