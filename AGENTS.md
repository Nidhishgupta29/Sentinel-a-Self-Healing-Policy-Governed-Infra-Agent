# Sentinel agent rules

1. Work on only the currently requested phase.
2. Create or update tests before implementation code.
3. Stop after the phase and wait for explicit verification before starting another phase.
4. Do not add features, dependencies, endpoints, or infrastructure outside the phase specification.
5. Keep intentional vulnerabilities isolated under `faults/`, clearly labeled, and never wire them into the normal application path.
6. Never place credentials, tokens, or other secrets in source, tests, fixtures, or documentation.
7. Every claimed check must have been run and its result reported.
