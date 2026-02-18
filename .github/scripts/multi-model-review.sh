#!/usr/bin/env bash
set -euo pipefail

# Multi-Model Code Review via GitHub Copilot CLI
# Dispatches PR review to GPT and Claude via copilot CLI,
# then synthesizes findings into a single consolidated comment.

# Required env vars: PR_NUMBER, REPO, GH_TOKEN

if [[ -z "${PR_NUMBER:-}" ]]; then
  echo "ERROR: PR_NUMBER not set" >&2
  exit 1
fi

if ! [[ "$PR_NUMBER" =~ ^[0-9]+$ ]]; then
  echo "ERROR: PR_NUMBER must be a positive integer, got: $PR_NUMBER" >&2
  exit 1
fi

if [[ -z "${REPO:-}" ]]; then
  echo "ERROR: REPO not set" >&2
  exit 1
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

MODELS=("gpt-5.3-codex" "claude-opus-4.6")
MODEL_LABELS=("gpt-5.3-codex" "claude-opus-4.6")

# Gather PR metadata for the context preamble
PR_META=$(gh pr view "$PR_NUMBER" --repo "$REPO" \
  --json title,body,additions,deletions,changedFiles,baseRefName,headRefName 2>/dev/null || echo "{}")

PR_TITLE=$(echo "$PR_META" | jq -r '.title // "unknown"')
PR_ADDITIONS=$(echo "$PR_META" | jq -r '.additions // 0')
PR_DELETIONS=$(echo "$PR_META" | jq -r '.deletions // 0')
PR_CHANGED=$(echo "$PR_META" | jq -r '.changedFiles // 0')
PR_BASE=$(echo "$PR_META" | jq -r '.baseRefName // "main"')
PR_HEAD=$(echo "$PR_META" | jq -r '.headRefName // "unknown"')
PR_BODY=$(echo "$PR_META" | jq -r '.body // ""' | head -c 500)

echo "Reviewing PR #${PR_NUMBER}: ${PR_TITLE}"
echo "  ${PR_CHANGED} files changed, +${PR_ADDITIONS}/-${PR_DELETIONS}"
echo "  ${PR_BASE} <- ${PR_HEAD}"

# Build the review prompt -- models fetch their own diffs via gh commands
read -r -d '' REVIEW_PROMPT <<'PROMPT_EOF' || true
You are a principal engineer performing a code review.

## Context for Reviewers

**Change Summary:** PR_TITLE_PLACEHOLDER
**Branch:** PR_HEAD_PLACEHOLDER -> PR_BASE_PLACEHOLDER
**Changed Files:** PR_CHANGED_PLACEHOLDER files, +PR_ADDITIONS_PLACEHOLDER/-PR_DELETIONS_PLACEHOLDER
**PR Description:** PR_BODY_PLACEHOLDER

---

Review Pull Request #PR_NUMBER_PLACEHOLDER in repository REPO_PLACEHOLDER.
Run `gh pr diff PR_NUMBER_PLACEHOLDER --repo REPO_PLACEHOLDER` to see the full diff.
Run `gh pr view PR_NUMBER_PLACEHOLDER --repo REPO_PLACEHOLDER` for the PR description.

IMPORTANT: You MUST run the gh commands above to get the actual diff. Do NOT review without reading the diff first.
For each changed file, try to browse the full file for context if possible.

Skip these files entirely -- do not review generated code, vendored dependencies, or lockfiles:
vendor/, node_modules/, third_party/, *.pb.go, *_pb2.py, *_generated.*, *_gen.go,
*.lock, package-lock.json, go.sum, *.min.js, *.min.css, *.snap, mocks/*
If a changed file matches these patterns, note "Skipped (generated/vendored)" and move on.

Review the code changes across these categories:

1) **Correctness & Logic**
   - Bugs, wrong assumptions, incorrect behavior
   - Off-by-one errors, race conditions, logic flaws
   - Does the code do what the PR description says it does?

2) **Error Handling & Edge Cases**
   - Missing error paths, unhandled exceptions
   - Boundary conditions, nil/null derefs, empty collections

3) **Security**
   - Injection vulnerabilities, auth bypass, secrets in code
   - Data exposure risks, insufficient input validation

4) **Testing**
   - Are there tests for the changes? Are they sufficient?
   - Untested code paths, missing edge case tests

5) **Performance & Resources**
   - Unnecessary allocations, N+1 queries, unbounded growth
   - Missing timeouts, connection leaks, resource cleanup

6) **API & Interface Design**
   - Breaking changes, backward compatibility, naming consistency

7) **Maintainability**
   - Readability, unnecessary complexity, dead code
   - Inconsistency with existing patterns

If a category has no findings, write "No issues found" for that category.

For EVERY finding, reference the specific file and line number(s).
Use the format: `path/to/file.go:42` or `path/to/file.go:42-55` for ranges.

Only flag issues INTRODUCED by this change. Pre-existing problems are out of scope.
If you claim a change could break something, identify the specific code that is provably affected.

Do NOT flag: missing docstrings on unchanged code, import ordering, variable naming preferences,
whitespace/formatting, const vs let style, adding logging to code that omits it.

For each finding, assign:
- Severity (1-10): 9-10 production outage, 7-8 normal-usage bug, 5-6 edge case, 3-4 perf/test gap, 1-2 minor
- Confidence (0.0-1.0): 0.9+ certain, 0.7-0.8 high, 0.4-0.6 medium, 0.1-0.3 speculative

Format each finding header as:
### [S:N C:X.X] Finding title | path/to/file:line | introduced

Keep tone matter-of-fact. State the problem, why it matters, suggest the fix.

At the END of your review, append:
---REVIEW_META---
findings_count: <total>
categories_clean: <comma-separated list of clean categories>
PROMPT_EOF

# Substitute placeholders with actual values
REVIEW_PROMPT="${REVIEW_PROMPT//PR_TITLE_PLACEHOLDER/$PR_TITLE}"
REVIEW_PROMPT="${REVIEW_PROMPT//PR_HEAD_PLACEHOLDER/$PR_HEAD}"
REVIEW_PROMPT="${REVIEW_PROMPT//PR_BASE_PLACEHOLDER/$PR_BASE}"
REVIEW_PROMPT="${REVIEW_PROMPT//PR_CHANGED_PLACEHOLDER/$PR_CHANGED}"
REVIEW_PROMPT="${REVIEW_PROMPT//PR_ADDITIONS_PLACEHOLDER/$PR_ADDITIONS}"
REVIEW_PROMPT="${REVIEW_PROMPT//PR_DELETIONS_PLACEHOLDER/$PR_DELETIONS}"
REVIEW_PROMPT="${REVIEW_PROMPT//PR_BODY_PLACEHOLDER/$PR_BODY}"
REVIEW_PROMPT="${REVIEW_PROMPT//PR_NUMBER_PLACEHOLDER/$PR_NUMBER}"
REVIEW_PROMPT="${REVIEW_PROMPT//REPO_PLACEHOLDER/$REPO}"

# Function to run a review with a specific model
review_with_model() {
  local model="$1"
  local output="$2"
  local label="$3"
  local start_time
  start_time=$(date +%s)

  echo "  Starting review with ${label}..."

  # copilot CLI in headless mode
  # stdout -> review file, stderr -> separate log for debugging
  timeout 600 copilot \
    -p "$REVIEW_PROMPT" \
    --model "$model" \
    --allow-all-tools \
    --no-custom-instructions \
    -s \
    < /dev/null > "$output" 2>"${output}.log" || true

  # If stdout is empty, copilot may have written everything to stderr
  if [[ ! -s "$output" ]] && [[ -s "${output}.log" ]]; then
    echo "  ${label}: stdout empty, checking stderr log..."
    cat "${output}.log" >&2
  fi

  local end_time
  end_time=$(date +%s)
  local elapsed=$(( end_time - start_time ))

  # Write timing metadata
  echo "$elapsed" > "${output}.timing"

  if [[ -s "$output" ]]; then
    echo "  ${label} completed in ${elapsed}s ($(wc -l < "$output") lines)"
  else
    echo "  ${label} produced no output after ${elapsed}s"
    echo "_Review failed or produced no output._" > "$output"
  fi
}

# Launch reviews in parallel
echo ""
echo "Dispatching reviews to ${#MODELS[@]} models..."

PIDS=()
for i in "${!MODELS[@]}"; do
  review_with_model "${MODELS[$i]}" "$WORKDIR/review-${MODEL_LABELS[$i]}.md" "${MODEL_LABELS[$i]}" &
  PIDS+=($!)
done

# Wait for all reviews
FAILURES=0
for pid in "${PIDS[@]}"; do
  if ! wait "$pid"; then
    (( FAILURES++ )) || true
  fi
done

echo ""
echo "All reviews complete. Failures: ${FAILURES}/${#MODELS[@]}"

# Check if we got any usable output
USABLE=0
REVIEW_CONTENT=""
for i in "${!MODEL_LABELS[@]}"; do
  label="${MODEL_LABELS[$i]}"
  file="$WORKDIR/review-${label}.md"
  timing_file="${file}.timing"
  elapsed="?"
  [[ -f "$timing_file" ]] && elapsed=$(cat "$timing_file")

  line_count=$(wc -l < "$file" 2>/dev/null || echo 0)
  if [[ -s "$file" ]] && [[ "$line_count" -gt 5 ]]; then
    (( USABLE++ )) || true
    REVIEW_CONTENT="${REVIEW_CONTENT}

--- BEGIN REVIEW FROM ${label} (${elapsed}s) ---
$(cat "$file")
--- END REVIEW FROM ${label} ---
"
  fi
done

if [[ "$USABLE" -eq 0 ]]; then
  echo "ERROR: All models failed to produce output" >&2
  gh pr comment "$PR_NUMBER" --repo "$REPO" --body "## Multi-Model Code Review

All review models failed to produce output. Check the workflow run for details."
  exit 1
fi

echo "Synthesizing ${USABLE} reviews..."

# Build the synthesis prompt
read -r -d '' SYNTH_PROMPT <<SYNTH_EOF || true
IMPORTANT: Output ONLY the consolidated review text below. Do NOT explain your process, do NOT use tools, do NOT describe what you will do. Just write the review directly as your response. Your entire output will be posted as a GitHub PR comment.

You are synthesizing code reviews from multiple AI models into a single consolidated review comment for a GitHub Pull Request.

**PR:** #${PR_NUMBER} -- ${PR_TITLE}
**Changed Files:** ${PR_CHANGED} files, +${PR_ADDITIONS}/-${PR_DELETIONS}

Below are the individual reviews from each model. Your job:

1. Deduplicate findings that reference the same code location with the same concern.
2. For duplicates, keep the best-written version and note which models agreed.
3. Drop findings with severity 1-2 (noise).
4. Drop findings with confidence below 0.4 unless multiple models flagged independently.
5. Sort by severity descending.
6. Preserve file:line references exactly as given.

${REVIEW_CONTENT}

Write a consolidated review in this exact format:

## Multi-Model Code Review

**PR:** #${PR_NUMBER} -- ${PR_TITLE}
**Models:** ${MODEL_LABELS[*]}

### Summary
<2-3 sentences: scope of changes, total findings after dedup, key themes>

### Critical Issues (Severity 7+)
For each finding:
#### [S:N C:X.X] Title | file:line | introduced
**Flagged by:** <model(s)>
**Problem:** <what's wrong>
**Impact:** <what breaks>
**Fix:** <specific suggestion>

### Other Findings (Severity 3-6)
Same format, grouped by category.

### Categories With No Issues
<List categories where all models found nothing>

### Action Items
- [ ] \`[S:N]\` \`file:line\` -- <action> -- [Category]
(sorted by severity descending)

If the reviews found no real issues, say so clearly -- do not invent problems.
Keep the output under 65000 characters (GitHub comment limit).
SYNTH_EOF

# Run synthesis -- no tools needed, just text processing
timeout 300 copilot \
  -p "$SYNTH_PROMPT" \
  --model "claude-opus-4.6" \
  --no-custom-instructions \
  --no-ask-user \
  -s \
  < /dev/null > "$WORKDIR/consolidated.md" 2>"$WORKDIR/synthesis.log" || true

if [[ ! -s "$WORKDIR/consolidated.md" ]]; then
  echo "WARNING: Synthesis failed, posting raw reviews instead"

  # Fallback: concatenate raw reviews
  {
    echo "## Multi-Model Code Review"
    echo ""
    echo "**PR:** #${PR_NUMBER} -- ${PR_TITLE}"
    echo "**Models:** ${MODEL_LABELS[*]}"
    echo ""
    echo "> Synthesis failed. Posting individual reviews below."
    echo ""
    echo "$REVIEW_CONTENT"
  } > "$WORKDIR/consolidated.md"
fi

# Truncate if over GitHub comment limit (65536 chars)
if [[ $(wc -c < "$WORKDIR/consolidated.md") -gt 65000 ]]; then
  head -c 64500 "$WORKDIR/consolidated.md" > "$WORKDIR/consolidated-truncated.md"
  {
    cat "$WORKDIR/consolidated-truncated.md"
    echo ""
    echo "---"
    echo "_Review truncated due to GitHub comment size limit._"
  } > "$WORKDIR/consolidated.md"
fi

# Post the review as a PR comment
echo "Posting consolidated review to PR #${PR_NUMBER}..."
gh pr comment "$PR_NUMBER" --repo "$REPO" --body-file "$WORKDIR/consolidated.md"

echo "Done. Review posted to PR #${PR_NUMBER}."
