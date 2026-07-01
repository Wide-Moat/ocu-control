<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Documentation standard

This is how we write the prose a human reads to understand code they did not
write: package READMEs, the architecture pages under `docs/architecture/`, and
the wire references. It applies to every committed `.md` file. Code comments
follow the same spirit but answer their own narrower question.

## The three rules

**Name the code, do not coordinate it.** In a sentence or a bullet, refer to a
thing by its identifier and its file: `Resolve` in `authz/resolver.go`, the
`mount-config` schema. A line number rots the moment someone edits above it, and
it tells a reader nothing they can search for. Where a name genuinely cannot
land the reader on the right spot, gather the line references into a single
`Code:` line at the end of that section — never mid-sentence.

**Let structure earn its shape.** A package gets a short README: what it is for,
the seam it sits behind, how to reach the rest. A deep reference page is for a
package that earns one — a wire protocol, a large surface, a non-obvious state
machine. Do not stamp the same six headings onto every package because a
template said to. Reach for a Mermaid diagram only when the flow is genuinely
non-linear; a straight chain of steps is a sentence, not a graph.

**State each fact once.** Put a fact where a reader will look for it, and put it
there only. The same sentence repeated across three files is three places to
forget when it changes. When two pages need the same fact, one owns it and the
other points.

## Mermaid that renders

When a diagram does earn its place, keep it parseable:

- Use `Note right of` or `Note left of`. Never `Note over` — it breaks the
  renderer here.
- Never put a `;` inside a `Note`.

## Register tells to avoid

These read as machine-written and dilute the page. Catch them in review:

- Every sentence the same length, every clause hung on the same em-dash beat.
- Throat-clearing: "it is worth noting that", "in order to", "it should be
  noted".
- A doc longer than the code it explains.
- A parenthetical list sold as complete — "handles all cases: A, B, C" — when
  the code handles more. Either enumerate honestly or describe the shape and
  stop.

Write the way you would explain it to the next maintainer at a whiteboard:
plainly, once, pointing at things by name.
