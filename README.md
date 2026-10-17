# SentinelOps AI

Evidence-driven cybersecurity investigation and response decision support
using entirely synthetic security events.

## Current status

The current implementation is a deterministic baseline. It does not yet invoke
Strands Decider 2B or Amazon Bedrock. It does not access live security systems
or execute containment actions.

## Requirements

Python 3.10 or later. The baseline uses only the Python standard library.

## Run the investigation

From the project directory:

```bash
python -m app.main --scenario suspicious_login_chain
python -m app.main --scenario benign_login
python -m app.main --scenario uncertain_activity
```

Optional filters:

```bash
python -m app.main --scenario suspicious_login_chain --user alex
python -m app.main --scenario suspicious_login_chain --source-ip 198.51.100.77
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Safety and limitations

- All events and IP reputation records are synthetic.
- Correlation indicates shared attributes, not proof of causation.
- Severity is a transparent heuristic and is not a confirmed attack verdict.
- Recommendations are simulated and require human approval where indicated.
- Investigation cost is expressed in illustrative relative units.
- No real containment, endpoint isolation, or network action is performed.
