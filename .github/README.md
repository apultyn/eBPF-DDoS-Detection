# GitHub configuration

- `main` accepts changes only through pull requests from `dev` with at least 3 approvals.
- `dev` accepts changes only through pull requests from `feature/*` branches.

In branch protection, require pull requests and the `Repository rules` status check for `main` and `dev`.
