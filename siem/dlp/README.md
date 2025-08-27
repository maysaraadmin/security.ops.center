# Data Loss Prevention (DLP) Module

The DLP module provides comprehensive data loss prevention capabilities for the SIEM system, including content inspection, contextual analysis, and policy-based protection.

## Features

- **Content Inspection**: Detect sensitive data using pattern matching and machine learning
- **Policy Management**: Define and manage DLP policies with flexible rules and actions
- **Multi-scope Protection**: Protect data across endpoints, network, cloud, and email
- **Actionable Responses**: Block, encrypt, quarantine, or redact sensitive data
- **Extensible Architecture**: Easily add new detection methods and actions

## Components

### 1. Core Engine (`core.py`)
The main DLP engine that coordinates content inspection and analysis.

### 2. Classifiers (`classifiers.py`)
Implements various classifiers for detecting sensitive content using different techniques.

### 3. Policy Management (`policies.py`)
Manages the lifecycle of DLP policies, including loading, validation, and evaluation.

### 4. Policy Actions (`actions.py`)
Implements actions that can be taken when a policy is triggered (block, encrypt, quarantine, redact).

### 5. Policy Enforcer (`enforcer.py`)
Enforces DLP policies across different scopes and coordinates policy evaluation and action execution.

## Usage

### Initializing the DLP System

```python
from siem.dlp import DLPEngine, PolicyEnforcer, PolicyScope

# Initialize the DLP engine
dlp_engine = DLPEngine()

# Initialize the policy enforcer with a directory containing policy files
enforcer = PolicyEnforcer(policy_dir="/path/to/policies")
```

### Defining Policies

Policies can be defined in YAML or JSON format. See `config/dlp_policy_templates.yaml` for examples.

### Evaluating Content

```python
# Example: Check email content
email_content = """
Please find attached the quarterly report containing SSNs:
- 123-45-6789
- 987-65-4321
"""

# Evaluate the content against DLP policies
results = enforcer.evaluate_content(
    content=email_content,
    scope=PolicyScope.EMAIL,
    context={
        "source": "smtp",
        "sender": "user@example.com",
        "recipients": ["external@example.org"],
        "subject": "Quarterly Report"
    }
)

# Process the results
for result in results:
    print(f"Policy: {result['policy_id']}")
    for action in result['actions_executed']:
        print(f"- {action['type']}: {action.get('message', '')}")
```

### Available Actions

- **Block**: Prevent the operation (e.g., block an email or file transfer)
- **Encrypt**: Encrypt the content
- **Quarantine**: Move the content to a secure location
- **Redact**: Remove or mask sensitive information
- **Notify**: Send alerts to administrators
- **Log**: Record the event for auditing

## Policy Examples

### Block Credit Card Numbers in Emails

```yaml
id: "block_cc_emails"
name: "Block Credit Card Numbers in Emails"
description: "Prevent emails containing credit card numbers from being sent"
scope: ["email"]
rules:
  - id: "block_cc_rule"
    name: "Block Credit Card Numbers"
    conditions:
      - type: "pattern_match"
        field: "content"
        pattern: "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\\d{3})\\d{11})\\b"
        sensitivity: "high"
    actions:
      - type: "block"
        params:
          message: "Email contains credit card numbers"
      - type: "notify"
        params:
          recipients: ["security@example.com"]
          subject: "Blocked email with credit card numbers"
```

### Encrypt Sensitive Files on Endpoints

```yaml
id: "encrypt_sensitive_files"
name: "Encrypt Sensitive Files on Endpoints"
description: "Automatically encrypt files containing sensitive data"
scope: ["endpoint"]
rules:
  - id: "encrypt_sensitive_content"
    name: "Encrypt Files with Sensitive Data"
    conditions:
      - type: "pattern_match"
        field: "content"
        pattern: "\\b(?:ssn|social.*security|tax.*id|credit.*card)"
        sensitivity: "high"
    actions:
      - type: "encrypt"
        params:
          algorithm: "AES-256"
      - type: "log"
        params:
          message: "Encrypted file containing sensitive data"
```

## Extending the DLP System

### Adding New Action Types

1. Create a new class that inherits from `PolicyAction` in `actions.py`
2. Implement the `execute()` method
3. Update the `ActionFactory` to support the new action type

### Adding New Condition Types

1. Add a new condition handler in the `_evaluate_condition` method of `PolicyEnforcer`
2. Update the policy schema validation if needed

## Best Practices

1. **Start with Logging**: When implementing new policies, start with logging before enabling blocking actions
2. **Test Thoroughly**: Test policies in a controlled environment before deploying to production
3. **Monitor Performance**: Be mindful of the performance impact of content inspection
4. **Regular Updates**: Keep patterns and ML models up to date with new threats
5. **Least Privilege**: Ensure the DLP system has only the permissions it needs

## License

[Your License Here]
