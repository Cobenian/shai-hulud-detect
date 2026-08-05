# npm-shrinkwrap-attack

`npm-shrinkwrap.json` is a published lockfile with the same format as
`package-lock.json`, but it was never collected into the lockfile inventory, so it
was never parsed. Same content as the working package-lock fixture, previously
reported clean.
