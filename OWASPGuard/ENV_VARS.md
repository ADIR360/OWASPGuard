## Environment variables

This project intentionally **does not** store secrets in the repository.

### Optional variables

- `HF_TOKEN`
  - **What**: Hugging Face access token
  - **Why**: higher download/rate limits when pulling models
  - **Where to set**:
    - **Locally**: export it in your shell before running OWASPGuard
    - **GitHub Actions**: add it as a repository secret named `HF_TOKEN`

### If you ever integrate external paid APIs

Keep keys out of the repo and inject them via environment variables:

- `STRIPE_API_KEY`
- `HIGHNOTE_LIVE_KEY`

In GitHub Actions, store them in **Repository secrets** with the same names and they will be injected by the CI workflow in `.github/workflows/ci.yml`.

