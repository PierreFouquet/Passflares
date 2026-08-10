# Guardrail tests

Source greps, not behavioural tests (#89 §5, #83 §3).

Everything in this directory reads project files as **text** and asserts that a
pattern is or is not present. Nothing here imports `src/` or `public/js/`, calls
a handler, or observes a runtime result. That is the whole distinction, and it
is enforced by `guardrails-are-not-behavioural.test.ts` rather than left to
convention.

## Why they are separated

They used to sit in `tests/backend/`, where 23 grep assertions were counted
alongside the behavioural suite and reported as one number. That number is what
people quote when asking "is this well tested?", and greps cannot answer it: a
rule saying `src/` contains no `eval(` tells you nothing about whether the
authorization check works. Two very different signals were being added together,
and the sum read as more coverage than existed.

They are worth keeping. Each rule encodes a threat-model decision that a static
review already made — no mixed-content URLs in shipped assets, no `*_hash`
compared with `===`, no inline `<script>`. A future change that re-introduces
one fails CI instead of shipping. They are cheap, they are fast, and they catch
a class of regression that behavioural tests genuinely miss.

What they are not is evidence that anything works.

## Running them

    npm run test:guardrails     # this directory only
    npm test                    # everything, guardrails included

They still run on every PR as part of `npm test`. Separating them changes how
the result is *read*, not whether it is checked.

## If one fires

Look at the change that triggered it before relaxing the rule. These encode
threat-model assumptions, not stylistic preferences — the fix is almost always
in the code that tripped the grep, not in the grep.
