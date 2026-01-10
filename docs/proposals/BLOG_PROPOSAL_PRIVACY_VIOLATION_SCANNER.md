# Blog Proposal: The AI Terms of Service Crisis

**Target Publication**: anshumanbhartiya.com / Boring AppSec Newsletter
**Format**: 2-part series
**Estimated Length**: Part 1: 1500 words, Part 2: 2000 words

---

## Series Overview

### Part 1: "The OAuth Arbitrage Crisis: When AI Wrappers Cross the Line"
**Hook**: A personal story about discovering the January 2026 drama
**Focus**: The problem, why it matters, who's affected

### Part 2: "Building an AI ToS Compliance Scanner: From Drama to Detection"
**Hook**: How SecureVibes' architecture inspired a new tool
**Focus**: Technical implementation, Ralph Wiggum TDD, results

---

## Part 1: "The OAuth Arbitrage Crisis: When AI Wrappers Cross the Line"

### Opening (Personal Anecdote)

```
Last week, I woke up to chaos on X.

My timeline was flooded with developers complaining about account bans,
cryptic error messages, and something about "spoofing Claude Code."
Within hours, I had three DMs asking the same question: "Did Anthropic
just break my coding setup?"

What I discovered was fascinating—and concerning. A whole ecosystem of
tools had quietly emerged that let developers use their $200/month Claude
Max subscription as if it were an unlimited API key. And Anthropic had
just shut it down.

This is the story of OAuth arbitrage, why it matters for AI security,
and how I ended up building a scanner to detect it.
```

### Section 1: What Actually Happened

- Thariq Shihipar's announcement on X
- The technical mechanism: OAuth tokens as API keys
- Tools involved: OpenCode, clawdbot, claude-code-router
- The $50k contract completed for $297 in API costs (cite Ralph Wiggum origin)
- Why Anthropic acted: bug reports, trust degradation, revenue protection

### Section 2: The Vibecoding Connection

```
Here's where it gets interesting for those of us in the vibecoding space.

Remember that friend who asked me to security-check his Replit app?
The one who inspired SecureVibes? Well, he messaged me again last week:

"Hey, I found this tool that lets me use Claude for free with my Max
subscription. Should I use it?"

My heart sank. This wasn't a security-illiterate user trying to cut
corners. This was someone who genuinely didn't understand the risk.
The tools made it seem legitimate. The documentation was professional.
The GitHub stars were in the thousands.

This is a new class of security problem: **ToS violations packaged as
developer tools.**
```

### Section 3: Why This Is a Security Problem

- Not just a billing issue—trust and ecosystem health
- Account bans = broken CI/CD pipelines
- Legal liability for enterprises
- Parallel to supply chain attacks (trusted tool, malicious behavior)
- The "I didn't know" defense doesn't work in compliance audits

### Section 4: The Target Audience

```
So who needs to care about this?

**Developers using AI coding tools**: If you're using anything other than
the official Claude Code CLI, you might be at risk. Not because the tool
is malicious, but because the line between "feature" and "exploit" is
blurry.

**Security teams reviewing AI tool adoption**: Your developers are
installing AI tools faster than you can review them. Some of those tools
might be routing credentials through unauthorized channels.

**AI tool builders**: If you're building on top of Claude, OpenAI, or
other AI APIs, you need to understand where the ToS boundaries are.
One bad pattern can get your users banned.

This isn't a problem for "other people." It's a problem for everyone
building with AI in 2026.
```

### Section 5: Teaser for Part 2

```
Next week, I'll show you how I built a scanner to detect these patterns.

Spoiler: I used the same multi-agent architecture from SecureVibes, a
technique called "Ralph Wiggum" that involves self-correcting AI loops,
and test-driven development with fixtures modeled on real-world violators.

The result? A tool that can scan any repository and tell you whether
it's compliant, potentially risky, or actively violating AI provider
terms of service.

And here's the twist: the tool itself is vibecoded. I didn't write a
single line of detection logic by hand.
```

### Closing

```
The January 2026 OAuth drama is a preview of conflicts to come.

As AI becomes infrastructure, the relationship between tool builders and
AI providers will become increasingly complex. We need tools to navigate
this complexity—not just for security, but for sustainability.

If you're using AI tools in production, you need visibility into what
they're actually doing with your credentials. That's what I'm building.

Stay tuned for Part 2, where we get technical.
```

---

## Part 2: "Building an AI ToS Compliance Scanner: From Drama to Detection"

### Opening

```
In Part 1, I explained the OAuth arbitrage crisis that hit in January 2026.
Today, I'm going to show you how I built a scanner to detect it.

Fair warning: this post is technical. We're going to talk about AST
parsing, regex patterns, test fixtures, and a development technique
called "Ralph Wiggum" that involves running Claude in an infinite loop
until it gets things right.

If that sounds fun to you, keep reading.
```

### Section 1: The Detection Challenge

- What patterns indicate a violation?
- Active vs. potential violations
- False positives: legitimate SDK usage vs. abuse
- The multi-language problem (Python, JS/TS, YAML configs)

### Section 2: Architecture Decision

```
When I started designing this scanner, I faced a classic architecture
question: should this be part of SecureVibes, or its own thing?

SecureVibes already has the infrastructure for multi-agent scanning.
I could add a "privacy-violation" agent alongside assessment, threat-
modeling, and code-review. The subagent pattern was proven.

But here's what changed my mind:

**Market positioning.** "AI ToS Compliance Scanner" is a broader value
proposition than "SecureVibes feature." It can be used by Anthropic
themselves, by CI/CD pipelines, by compliance teams who don't need a
full security scan.

**Funding narrative.** I want to work on this full-time. "I built a
tool that protects AI provider revenue and keeps developers compliant"
is more fundable than "I added a feature to my scanner."

**Technical separation.** ToS detection is fundamentally different from
security vulnerability detection. Mixing them creates architectural debt.

So I went with a standalone tool that SecureVibes can invoke as a
subagent. Best of both worlds.
```

### Section 3: Ralph Wiggum Development

```
Here's where it gets fun.

Ralph Wiggum is a technique from the Claude Code ecosystem. Named after
the Simpsons character who never gives up despite constant setbacks,
it works like this:

1. You give Claude a detailed prompt with clear success criteria
2. Claude works on the task
3. When Claude tries to exit, a hook blocks it and re-feeds the prompt
4. Claude sees its previous work (modified files, git history)
5. The loop continues until Claude outputs a "completion promise"

For TDD, this is perfect:

"Write failing tests. Implement feature. Run tests. If any fail, debug
and fix. Repeat until all green. Output: <promise>COMPLETE</promise>"

I set --max-iterations 30 as a safety net and let it run overnight.

The next morning? A working scanner with 87% test coverage.
```

### Section 4: The Detection Patterns

Technical deep-dive into:
- Environment variable regex patterns
- AST analysis for token manipulation
- Config file parsing (litellm, openrouter)
- Header spoofing detection
- Package dependency red flags

### Section 5: Test Fixtures Design

```
TDD requires good fixtures. I created a test suite modeled on real
violations:

fixtures/
├── active_violation/
│   ├── opencode_style/     # Header spoofing pattern
│   ├── clawdbot_style/     # OAuth subscription routing
│   └── litellm_proxy/      # Gateway with OAuth tokens
├── potential_violation/
│   ├── litellm_config/     # Gateway without OAuth usage
│   └── token_handling/     # Extraction without abuse
└── compliant/
    ├── native_sdk/         # Proper claude_agent_sdk usage
    └── api_key/            # Standard ANTHROPIC_API_KEY

The scanner must:
- Flag all active_violation/ repos as ACTIVE_VIOLATION
- Flag all potential_violation/ repos as POTENTIAL_VIOLATION
- Pass all compliant/ repos as COMPLIANT

Zero false positives on compliant. Zero false negatives on active.
That's the bar.
```

### Section 6: SecureVibes Integration

Show the subagent adapter pattern and how the tools work together.

### Section 7: Results & What's Next

- Scanned 50 public repos
- Found X active violations, Y potential violations
- Reached out to maintainers (responses?)
- Roadmap: OpenAI ToS, Google AI Studio, generic framework

### Closing

```
The OAuth arbitrage drama taught me something about the AI ecosystem
we're building.

The incentives are misaligned. Tool builders want to provide value.
AI providers want to protect revenue. Developers want to build fast
and cheap. These goals collide when the tooling makes ToS violations
easy and compliance hard.

I built this scanner because visibility is the first step toward
fixing misaligned incentives. If developers can see that a tool
routes their OAuth tokens through unauthorized channels, they can
make informed decisions.

If you want to check your own repositories—or tools you're considering
adopting—the scanner is open source:

[GitHub link]

And if you work at an AI company and want to talk about integrating
this into your developer tooling, DM me.

This is the kind of problem I want to work on full-time. If you know
anyone who might want to fund compliance tooling for AI, I'm all ears.
```

---

## Key Stylistic Elements (Matching Existing Blog)

1. **Personal anecdote opening**: Story from X/Twitter drama
2. **Problem-first framing**: Explain crisis before solution
3. **Clear target audience section**: Who should care and why
4. **Technical depth in Part 2**: Code examples, architecture decisions
5. **Self-deprecating vibecoding reference**: "I didn't write a single line"
6. **Call to action**: Open source link, invitation to collaborate
7. **Funding narrative woven in**: Authentic, not pushy

---

## Promotion Plan

1. **X/Twitter thread**: Summarize the drama, link to Part 1
2. **Hacker News**: "Show HN: AI ToS Compliance Scanner"
3. **Reddit**: r/MachineLearning, r/netsec
4. **Direct outreach**: Anthropic DevRel, affected tool maintainers
5. **Podcast mention**: Boring AppSec if timing works

---

## Timeline

- Week 1: Write Part 1, implement core scanner
- Week 2: Write Part 2, complete scanner with Ralph Wiggum
- Week 3: Edit, publish Part 1, promote
- Week 4: Publish Part 2, launch scanner, outreach
