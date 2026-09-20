module.exports = {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "type-enum": [
      2,
      "always",
      [
        "feat",
        "fix",
        "docs",
        "test",
        "refactor",
        "perf",
        "build",
        "ci",
        "chore",
        "revert"
      ]
    ],
    "scope-enum": [
      1,
      "always",
      [
        "xdp",
        "ebpf",
        "loader",
        "userspace",
        "detector",
        "maps",
        "tests",
        "docs",
        "ci",
        "repo"
      ]
    ],
    "subject-case": [
      2,
      "never",
      ["sentence-case", "start-case", "pascal-case", "upper-case"]
    ],
    "header-max-length": [2, "always", 72]
  }
};
