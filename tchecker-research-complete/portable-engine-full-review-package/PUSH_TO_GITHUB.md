# Pushing this to your GitHub repo

Run these locally (where your git auth already works). This sandbox can't push —
it has no access to your credentials, and you should never paste a token into a chat.

## Option A — brand-new repo
1. Create an empty repo on github.com (no README/license, so history stays clean).
2. Unzip this package locally, then in the unzipped folder:

    git init
    git add .
    git commit -m "Portable provenance engine + class-aware PHP engine (baseline b1a864d941d8f8ab)"
    git branch -M main
    git remote add origin https://github.com/<you>/<repo>.git
    git push -u origin main

## Option B — existing repo
    cd <your-existing-clone>
    # copy the unzipped package contents in, then:
    git add .
    git commit -m "Add portable provenance engine + PHP class-isolation engine"
    git push

## Notes
- .gitignore is included: build/, target/, *.class, __pycache__/, node_modules/,
  and Joern intermediates (cpg.bin, raw/, jsraw/) are excluded. Those regenerate.
- Joern itself is NOT in the repo (external dependency) and shouldn't be committed.
- Repo size ~29 MB, largest file ~895 KB (the PHP engine) — well within GitHub limits.
- If your account uses SSH, swap the remote URL for git@github.com:<you>/<repo>.git
- If push is rejected for auth: create a Personal Access Token (GitHub → Settings →
  Developer settings → Tokens) and use it as the password, or set up an SSH key.
