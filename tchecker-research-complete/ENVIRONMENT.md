# ENVIRONMENT.md

Exact versions installed and successfully used during this packaging pass.

## java -version
```
openjdk version "21.0.10" 2026-01-20
OpenJDK Runtime Environment (build 21.0.10+7-Ubuntu-124.04)
OpenJDK 64-Bit Server VM (build 21.0.10+7-Ubuntu-124.04, mixed mode, sharing)
```

## python3 --version
```
Python 3.12.3
```

## node --version
```
v22.22.2
```

## Joern
```
JOERN_HOME used: /home/claude/work/joern-cli
Version: 4.0.608 (pinned; jar names confirm io.joern.*-4.0.608)
NOTE: `joern --version` is NOT a supported flag -- it is silently ignored and the
binary drops into an interactive REPL. To check the version non-interactively:
  echo "" | timeout 60 $JOERN_HOME/joern 2>&1 | grep "Version:"
This was found by actually testing the install, not assumed.
```

## OS / kernel
```
Linux vm 6.18.44-fc-v21 #1 SMP PREEMPT_DYNAMIC @0 x86_64 x86_64 x86_64 GNU/Linux
```

## Python packages
```
No third-party Python packages are required. adjudicate_js.py and all test/verify
scripts use only the standard library (json, pathlib, os, sys, csv).
stdlib-only confirmed for adjudicator; python 3.12.3
```

## UPDATE 2026-08-24: joern-install.sh removed (third-party)
The upstream Joern installer previously vendored at ./joern-install.sh was removed as
downloadable third-party code. To provision the pinned toolchain: download
joern-cli-linux-x86_64.zip from https://github.com/joernio/joern/releases/tag/v4.0.608
(or run upstream joern-install.sh with --version=v4.0.608), unzip, and set JOERN_HOME
to the extracted joern-cli directory. No local modifications were ever made to Joern
4.0.608 itself; all project logic lives in the exporter scripts (.sc) and normalizers.
