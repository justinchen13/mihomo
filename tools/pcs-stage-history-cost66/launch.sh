#!/bin/bash
# CI-only: never point at production binaries/collectors. Called only after review.
set -euo pipefail
umask 077
[[ $# == 2 ]] || { echo 'usage: launch.sh /absolute/manifest.json SHA256' >&2; exit 2; }
[[ $(id -u) == 0 ]] || { echo 'sudo required for owned namespaces/cgroups' >&2; exit 2; }
[[ ${GITHUB_ACTIONS:-} == true && -n ${GITHUB_WORKSPACE:-} ]] || { echo 'dedicated GitHub Actions runner required' >&2; exit 2; }
exec timeout --signal=TERM --kill-after=30s 900s /usr/bin/python3 "$(dirname "$(realpath "$0")")/run.py" --manifest "$1" --manifest-sha "$2"
