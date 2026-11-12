# Backend Prime

Take an app backend from built to prime with a builder AI. Prime means every attack fails and every test passes on a fresh independent re-run. Proven on one backend run, 53 attacks passing on an independent re-run.

## Define prime and the three roles

- Prime means every attack fails and every test passes on a fresh independent re-run, not on the builder's word alone.

- Three roles take part. The owner rules and gives the separate go for anything live. The builder builds the missing pieces and then attacks its own work. The verifier audits the builder's report against the real artifacts and re-runs every suite fresh.

- Never treat a builder's pass count as verified until the verifier has re-run it. A report is a claim, and the re-run is the proof.

## Freeze the source of truth

- Write the brief before the builder starts. Pin the repo to one commit hash and name it in the brief. Mark older snapshots as reference only.

- Forbid pushes to any remote and forbid writes to the live database. The builder works on copies and scratch databases only.

- Forbid secrets in files. Test keys and test cards only. Live keys stay with the owner and go in as secrets at deploy time.

- Require the deliverables up front. A zip with every new and changed file, new SQL as separate files, and a written report with files changed, pass and fail counts, each attack with its outcome per round, and open items.

- Name the rulings that must survive, in the owner's own words. A ruling is not a suggestion, and the builder must not soften it.

- Build the bundle from the pinned repo and the live migrations. Copy each live migration byte for byte and check the copies with cmp. Add the reference docs and the app wrapper. Write a short bundle readme that states the hard rules.

## Brief the builder in one message

- Send one consolidated message that holds the decision and the rest of the work together. The owner pays per prompt, so never split one round into several messages.

- Order the work build first, then attack. Attacks can only test what already exists, so a missing piece gets built before the round that tests it.

- Tell the builder to put every deliverable in a durable output directory, never in temp storage alone. Anything that lives only in a chat transcript or a temp folder is one lost session from gone.

## Attack in phases and report honestly

- Have the builder attack in phases. First the payment webhook core with the real payment library. Then the purchase verification core. Then the database, with the full migration chain applied to a scratch Postgres.

- Require one result per attack with its evidence. A pass needs the exact error, message, or count that proves it, not a bare pass word.

- Include the refund and revocation path in the attack list. A refunded purchase that keeps its grant is a failed attack, and an acknowledge call that swallows its errors needs a retry or a log.

- Require the builder to state plainly what is not done. No attack rounds run, no report, no zip, and no download link are all reportable facts, not failures to hide.

- Require the builder to label every suspicion as unverified. A harness interaction, a test sequencing guess, or a stale assertion stays a suspicion until a bisect or a re-run settles it.

- Require the caveats in the report. A classifier that cannot run locally, a test base rebuilt without some migrations, and glue code that was read but never executed all belong in writing.

## Audit the report, then verify it yourself

- Read the builder's report against the real code. Check each pass count against its evidence. Check each claim about the shipped code by reading that code.

- Chase every contradiction to a decision. When the shipped code caps stakes and an old doc says let balances go negative, put the choice to the owner and record the ruling.

- Extract the delivered zip and read its report in full. Confirm the counts in the report match the result files inside the zip.

- Re-run every suite fresh on your own machine with the real libraries and a real database. Compare your result files with the builder's, name by name and pass by pass.

- Compare every source of truth file byte for byte with the bundle you sent. The builder must not change the repo, the live migrations, or the reference docs.

- Read the new code yourself, including the server glue that was never executed. Check the decision logic, the dedup path, the unknown user path, and the error paths.

- Check that every dependency the builder names actually exists. Query the package registry for each one before you trust the install step. A package that returns 404 breaks the whole client wiring.

- Confirm the zip holds one version of each deliverable. Two copies of the same function with different guards is a defect, and the unguarded copy must go.

- Scan the zip for secrets. Placeholders in docs and public publishable keys are fine. Real secret keys, webhook secrets, and service account JSON are not.

## Report the verdict and gate the deploy

- Report what passed only after your own re-run confirms it. Name the counts and say they were re-run fresh.

- Report every defect with its evidence. A missing package gets its registry response. A duplicate file gets both paths and the diff between them. An unbuilt attack gets named as unbuilt, not as passed.

- Name the open items. A refund path that was never built, a wrapper that was never executed, and a classifier that cannot run locally all stay open until they are built or ruled out.

- Hand the owner a deploy checklist with the order of operations. Migrations first, then function deploys, then secrets, then dashboard settings, then the promo SQL only when ready.

- Nothing goes live without the owner's separate go. A verified zip is not a deploy, and a passing suite is not permission to push.

## Available connectors

- [GitHub](/opt/hatch/connectors/github/CONNECTOR.md) for reading the repo at a pinned commit and checking what the builder changed.

- [Google Drive](/opt/hatch/connectors/google_drive/CONNECTOR.md) for fetching a bundle zip the owner uploaded.

- Use `muse.connector_search` to find other connectors and `muse.skill_search` to find related skills.

- If nothing here fits, look on the web for a maintained API or MCP server and set it up with [Custom Connectors and MCPs](/opt/muse/skills/custom-connector-setup/SKILL.md), or build a custom connector.

## Alternatives for better results

- When the builder's budget runs out mid-round, ask for the durable directory path and the state of each phase before the next prompt, so no round restarts from zero.

- When a package the builder chose does not exist, have the builder name the replacement, install it, and build with it before the next attack round, instead of trusting the package name on paper.

- When the owner rules on a design question mid-round, fold the ruling into the same message as the next instruction, so the round does not cost an extra prompt.
