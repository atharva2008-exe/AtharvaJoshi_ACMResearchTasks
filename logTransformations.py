import re
import random


# ─── Contextual Meme Library ────────────────────────────────────────────────
CONTEXTUAL_MEMES = {
    # Database & Connection issues
    r"(db|database|connection|refused|timeout|unreachable)": [
        "the database said no ❌",
        "connection said 'nah fam'",
        "timeout speedrun any%",
        "database.exe has stopped responding",
        "bro this connection lost",
    ],
    # Crashes & Errors
    r"(crash|fatal|panic|segfault|abort)": [
        "💀 didn't make it past Q&A",
        "gg ez clapped",
        "bro said YEET and left",
        "that's tuff 🚬",
        "caught slipping in production",
    ],
    # OOM / Memory
    r"(oom|out of memory|overflow|memory leak)": [
        "memory said 'we full'",
        "stack overflow detected (literally)",
        "RAM said nope 💾",
        "memory exhaustion speedrun",
    ],
    # Authentication & Security
    r"(auth|unauthorized|forbidden|credentials|security|breach)": [
        "unauthorized access? more like un-axe-thorized",
        "permission denied but not in a fun way",
        "security update: exists | devs: 🙈",
        "this giving zero-day energy",
        "we are NOT cooked (we r cooked)",
    ],
    # Deployment & Success
    r"(deploy|release|shipped|live|prod)": [
        "shipped unsupervised",
        "production moment of truth",
        "deploy go brrr 🚀",
        "live and unfiltered",
        "this was not tested 💀",
    ],
    # Health & Status
    r"(health|operational|ready|up|healthy)": [
        "all green flags ✅",
        "peak performance vibes",
        "we actually cooked 🍳",
        "systems are sigma'd up",
    ],
    # Warnings & Slow Perf
    r"(warn|slow|latency|timeout|delayed)": [
        "red flags but make it yellow 🟡",
        "speed? never heard of her",
        "this slow but it moved",
        "performance is a suggestion",
        "big O notation said yikes",
    ],
    # Retries & Recovery
    r"(retry|retry|fallback|recovery|reconnect)": [
        "bro tried again",
        "the comeback kid",
        "this persists ✨",
        "fail fast but also slow later",
        "plot twist: it worked this time",
    ],
    # Generic fallback
    "default": [
        "no cap fr fr",
        "it's giving... chaos",
        "skill issue detected",
        "lowkey based ngl",
        "brainrot moment real",
        "ohio certified",
        "rent free in the server's head",
        "L + ratio + didn't even paginate",
        "real and valid behavior (it was not)",
        "tell me you didn't test without telling me",
    ],
}

# ─── Severity keyword maps ───────────────────────────────────────────────────
RED_KEYWORDS = re.compile(
    r"\b(error|exception|critical|fatal|fail(ed|ure)?|crash(ed)?|timeout|"
    r"unauthori[zs]ed|forbidden|panic|corrupt(ed)?|overflow|null\s*pointer|"
    r"segfault|abort(ed)?|terminated|down|unreachable|refused)\b",
    re.IGNORECASE,
)
GREEN_KEYWORDS = re.compile(
    r"\b(success(ful(ly)?)?|started|connected|ready|complete(d)?|"
    r"authenticated|deployed|healthy|up|ok|passed|done|cached|warm)\b",
    re.IGNORECASE,
)

# ─── Timestamp patterns (for stripping before dedup comparison) ───────────────
TIMESTAMP_PATTERNS = [
    # ISO 8601 / common datetime with optional timezone
    re.compile(
        r"\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    ),
    # Unix epoch (10-13 digit) – only when at start of line or after bracket
    re.compile(r"(?:^|[\[\s])\d{10,13}(?:\.\d+)?(?=\s|])"),
    # dd/Mon/yyyy:HH:MM:SS (Apache)
    re.compile(r"\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}"),
    # Month dd HH:MM:SS (syslog)
    re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"),
]

# ─── Date normalisation (ISO → normalised readable) ─────────────────────────
DATE_NORM = re.compile(
    r"(\d{4})[-/](\d{2})[-/](\d{2})[T\s](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?"
)

# ─── Severity level normalisation ──────────────────────────────────────────
LEVEL_NORM = {
    "WARN": "WARNING", "warn": "WARNING", "warning": "WARNING",
    "ERR": "ERROR", "err": "ERROR", "error": "ERROR",
    "CRITICAL": "CRITICAL", "critical": "CRITICAL",
    "FATAL": "FATAL", "fatal": "FATAL",
    "INFO": "INFO", "info": "INFO",
    "DEBUG": "DEBUG", "debug": "DEBUG",
    "TRACE": "TRACE", "trace": "TRACE",
}
LEVEL_PATTERN = re.compile(
    r"\b(WARN(?:ING)?|warn(?:ing)?|ERR(?:OR)?|err(?:or)?|"
    r"CRITICAL|critical|FATAL|fatal|INFO|info|DEBUG|debug|TRACE|trace)\b"
)

# ─── PII / secrets masking patterns ─────────────────────────────────────────
MASK_PATTERNS = [
    # Email addresses
    (re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"), "[EMAIL]"),

    # IPv4 (before IPv6 to avoid partial matches)
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP]"),

    # IPv6 — full 8-group form, or compressed with "::" (must have ≥2 colon-separated groups)
    (re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){2,7}(?::[0-9a-fA-F]{1,4}){1,6}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
    ), "[IPv6]"),

    # Credit card: 13-19 digits, optionally separated by spaces/dashes
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[CC_NUMBER]"),

    # Generic API key / secret heuristic: long alphanumeric tokens (20+ chars)
    # preceded by key= / secret= / token= / api_key= etc.
    (re.compile(
        r"(?:api[_-]?key|secret|token|auth|password|passwd|pwd|bearer|access[_-]?key"
        r"|client[_-]?secret|private[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+._\-]{16,})['\"]?",
        re.IGNORECASE
    ), lambda m: m.group(0).replace(m.group(1), "[REDACTED]")),

    # AWS access key pattern (AKIA...)
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "[AWS_KEY]"),

    # JWT tokens  (three base64 segments separated by dots)
    (re.compile(
        r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"
    ), "[JWT]"),

    # SSN (US)
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),

    # Phone numbers — must start with + or have typical tel structure (not bare digit runs)
    # Requires either a leading +, or parenthesised area code, to avoid eating date fragments
    (re.compile(r"(?<!\d)(?:\+\d{1,3}[\s\-])?(?:\(\d{1,4}\)[\s\-])?\d{3,5}[\s\-]\d{3,5}[\s\-]\d{2,6}(?!\d)"), "[PHONE]"),
]


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def transform_logs(log_text: str) -> str:
    """
    Process a raw log string through:
      1. PII / secret masking
      2. Consecutive duplicate collapsing (timestamp-agnostic)
      3. Timestamp & severity level standardisation
      4. Severity emoji tagging  🔴 🟡 🟢
      5. Random meme/brainrot reactions on a subset of lines
    
    Returns the processed log as a single string.
    """
    lines = log_text.splitlines()
    processed = []

    for line in lines:
        line = _mask(line)
        line = _standardize(line)
        processed.append(line)

    deduped = _deduplicate(processed)
    tagged  = [_tag_severity(line) for line in deduped]
    memed   = _sprinkle_memes(tagged)

    return "\n".join(memed)


# ─── Step 1: Masking ─────────────────────────────────────────────────────────

def _mask(line: str) -> str:
    for pattern, replacement in MASK_PATTERNS:
        if callable(replacement):
            line = pattern.sub(replacement, line)
        else:
            line = pattern.sub(replacement, line)
    return line


# ─── Step 2: Standardisation ─────────────────────────────────────────────────

def _standardize(line: str) -> str:
    # Normalise datetime to ISO 8601 readable
    line = DATE_NORM.sub(_format_date, line)

    # Normalise log level labels
    line = LEVEL_PATTERN.sub(lambda m: LEVEL_NORM.get(m.group(0), m.group(0).upper()), line)

    return line


def _format_date(m: re.Match) -> str:
    year, month, day = m.group(1), m.group(2), m.group(3)
    hh, mm, ss = m.group(4), m.group(5), m.group(6)
    tz = m.group(7) or ""
    return f"{year}-{month}-{day} {hh}:{mm}:{ss}{tz}"


# ─── Step 3: Deduplication ───────────────────────────────────────────────────

def _strip_timestamps(line: str) -> str:
    """Return line with all timestamps removed for structural comparison."""
    stripped = line
    for pat in TIMESTAMP_PATTERNS:
        stripped = pat.sub("", stripped)
    return stripped.strip()


def _deduplicate(lines: list[str]) -> list[str]:
    """Collapse consecutive lines that are identical ignoring timestamps."""
    result   = []
    prev_key = None
    count    = 1
    prev_line = None

    for line in lines:
        key = _strip_timestamps(line)
        if key == prev_key and prev_key is not None:
            count += 1
        else:
            if prev_line is not None:
                result.append(prev_line if count == 1 else f"{prev_line}  ×{count}")
            prev_key  = key
            prev_line = line
            count     = 1

    # flush last group
    if prev_line is not None:
        result.append(prev_line if count == 1 else f"{prev_line}  ×{count}")

    return result


# ─── Step 4: Severity tagging ────────────────────────────────────────────────

def _tag_severity(line: str) -> str:
    if RED_KEYWORDS.search(line):
        return f"🔴 {line}"
    if GREEN_KEYWORDS.search(line):
        return f"🟢 {line}"
    return f"🟡 {line}"


# ─── Step 5: Context-aware meme injection ─────────────────────────────────

def _get_contextual_meme(line: str) -> str | None:
    """Match line against context patterns and return a relevant meme, or None."""
    line_lower = line.lower()
    
    # Check contextual patterns (longest first for better specificity)
    for pattern_str in sorted(CONTEXTUAL_MEMES.keys(), key=len, reverse=True):
        if pattern_str == "default":
            continue
        if re.search(pattern_str, line_lower, re.IGNORECASE):
            return random.choice(CONTEXTUAL_MEMES[pattern_str])
    
    return None


def _sprinkle_memes(lines: list[str]) -> list[str]:
    """Add contextual memes to ~25% of lines based on log content."""
    result = []
    for line in lines:
        if random.random() < 0.2:  # ~1 in 5 lines gets a reaction
            # Try context-aware selection first
            meme = _get_contextual_meme(line)
            # Fall back to generic pool if no context match
            if meme is None:
                meme = random.choice(CONTEXTUAL_MEMES["default"])
            result.append(f"{line}  // {meme}")
        else:
            result.append(line)
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  DEMO
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE_LOG = """
2024-01-15T08:23:11.342Z INFO  Server started on 192.168.1.105:8080
2024-01-15T08:23:11.400Z info  Server started on 192.168.1.105:8080
2024-01-15T08:23:11.510Z info  Server started on 192.168.1.105:8080
2024-01-15T08:23:14.001Z DEBUG User login attempt for user@example.com from 10.0.0.22
2024-01-15T08:23:14.221Z INFO  Authentication successful for user@example.com
2024/01/15 08:24:02 WARN  Slow DB query detected (1420ms)
2024/01/15 08:24:03 WARN  Slow DB query detected (1390ms)
2024/01/15 08:24:03 WARN  Slow DB query detected (1410ms)
2024-01-15T08:25:00Z ERROR Connection refused to 203.0.113.55:5432 — retrying...
2024-01-15T08:25:01Z ERROR Connection refused to 203.0.113.55:5432 — retrying...
2024-01-15T08:25:02Z ERROR Connection refused to 203.0.113.55:5432 — retrying...
2024-01-15T08:25:10Z CRITICAL DB host 203.0.113.55 unreachable after 5 retries. Aborting.
2024-01-15T08:26:00Z INFO  Fallback cache hit. Serving stale data.
2024-01-15T08:27:15Z DEBUG Payment initiated: card 4111 1111 1111 1111, user billing@corp.io
2024-01-15T08:27:18Z INFO  Stripe webhook verified. Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
2024-01-15T08:27:19Z INFO  API call with api_key=sk-AbCdEfGhIjKlMnOpQrStUvWxYz123456
2024-01-15T08:27:20Z INFO  AWS credentials: AKIAIOSFODNN7EXAMPLE used
2024-01-15T08:30:00Z INFO  Health check passed. All systems operational.
2024-01-15T08:30:00Z info  Health check passed. All systems operational.
Jan 15 08:31:00 syslog kernel: OOM Killer terminated process nginx (pid 4821)
2024-01-15T08:32:55Z INFO  Deployment complete. Version 3.2.1 is live.
""".strip()

    output = transform_logs(SAMPLE_LOG)
    print(output)