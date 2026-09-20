# Contributing

## Local Setup

Install the development tooling after cloning the repository:

```sh
npm install
```

The `prepare` script installs Husky and connects Git to the versioned hooks in
`.husky/`. The commit hook can be bypassed locally, so GitHub Actions remains the
authoritative check for pull requests.

## Branch Policy

- `main` accepts pull requests only from `dev` and requires at least three
  approvals.
- `dev` accepts pull requests only from `feature/*` branches.

Configure branch protection for `main` and `dev` to require pull requests and
the `Repository rules` and `Commit conventions` status checks.

## Commit Messages

Commits use the Conventional Commits format:

```text
type(scope): short imperative summary
```

The scope is optional. Keep the summary lowercase and imperative, and keep the
complete header at or below 72 characters.

Examples:

```text
feat(xdp): add packet counter map
fix(loader): handle missing bpffs mount
docs(repo): document branch policy
ci(repo): enforce commit conventions
test(detector): add syn flood threshold tests
```

Allowed types:

- `feat`: new behavior
- `fix`: bug fix
- `docs`: documentation only
- `test`: tests
- `refactor`: code restructuring without a behavior change
- `perf`: performance improvement
- `build`: build system or dependency changes
- `ci`: GitHub Actions or automation changes
- `chore`: maintenance
- `revert`: revert a previous change

Suggested scopes are `xdp`, `ebpf`, `loader`, `userspace`, `detector`, `maps`,
`tests`, `docs`, `ci`, and `repo`. Both types and scopes are defined in [commitlint.config.cjs](commitlint.config.cjs) file.

Husky blocks invalid messages after dependencies have been installed:

```sh
git commit -m "bad message"
git commit -m "feat(xdp): add packet counter map"
```

To validate the most recent commit manually, run:

```sh
npm run commitlint:range
```

## Pull Requests

Pull request titles follow the same format and rules as commit messages:

```text
type(scope): short imperative summary
```

Create feature work from `dev` using a `feature/*` branch. Complete the pull
request template and describe any validation performed. Use `Not applicable`
when the repository does not yet have a relevant automated check.

GitHub Actions validates every commit in the pull request and its title using
`commitlint.config.cjs`.
