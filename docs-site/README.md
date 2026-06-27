# Warden docs site

Public documentation for `sellinnate/warden`, built with [docmd](https://docmd.io)
and deployed to `laravel-warden.selli.io`.

## Develop

```bash
cd docs-site
npx @mgks/docmd dev      # live dev server
npx @mgks/docmd build    # build static site to ./site
npx @mgks/docmd validate # check internal links
```

## Structure

- `docs/` — the markdown source pages (tracked).
- `docmd.config.json` — site config and navigation.
- `assets/` — static assets; put the banner at `assets/images/banner.png`.
- `site/` — build output (gitignored).
