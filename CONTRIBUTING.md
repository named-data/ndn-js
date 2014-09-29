Working on ndn-js
=================


Publishing a new release to GitHub and NPM
------------------------------------------

    npm version patch  # minor, major
    git push origin master --tags
    npm publish

The `npm version patch` increases the version number in preparation for a new
release via `npm publish`. It modifies [`package.json`](./package.json), and
creates a new Git commit and Git tag.

After `npm version ...`, make sure to both `git push --tags` to GitHub **and**
run `npm publish`, so that the versions published on https://www.npmjs.org/
and https://github.com/named-data/ndn-js/releases match up exactly.
