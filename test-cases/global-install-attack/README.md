# global-install-attack

A compromised package present on disk with **nothing declaring it as a dependency** —
the shape of a global install (`npm i -g keyv@6.0.0`, i.e. `$(npm root -g)`), and
equally of a `node_modules` tree whose lockfile is absent or stale.

`check_packages` only ever read `dependencies` / `devDependencies` blocks, so a
manifest's own `name` + `version` was never matched. The payload sat on disk and
nothing pointed at it, so the scan reported clean. This matters most for exactly
the directory people scan to check their globally installed CLIs.

No top-level `package.json` here on purpose: that is what a global root looks like.
Inert — a name and a version string, nothing else.
