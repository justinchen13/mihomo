#!/bin/bash
# Invoke later in an explicitly frozen CI build phase, never during ABBA.
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: build-client.sh MODULE_SOURCE OUTPUT_BINARY PROVENANCE_JSON' >&2; exit 2; }
fixture_source=$(realpath "$(dirname "$0")/client-v2.go")
module_source=$(realpath "$1")
output_binary=$(realpath -m "$2")
provenance_output=$(realpath -m "$3")
[[ ! -e $output_binary && ! -e $provenance_output ]]
export CGO_ENABLED=0 GOTOOLCHAIN=local GOWORK=off GOMAXPROCS=1 GOAMD64=v1 GOMEMLIMIT=384MiB
cd "$module_source"
[[ $(go env GOVERSION) == go1.25.6 ]]
locks_before=$(sha256sum go.mod go.sum)
go build -p 1 -mod=readonly -trimpath -buildvcs=false -o "$output_binary" "$fixture_source"
[[ $(sha256sum go.mod go.sum) == "$locks_before" ]]
python3 - "$fixture_source" "$output_binary" "$provenance_output" <<'PY'
import sys,json,hashlib,os
from pathlib import Path
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
r={'source_sha256':sha(sys.argv[1]),'binary_sha256':sha(sys.argv[2]),'go_version':'go1.25.6','go_mod_sha256':sha('go.mod'),'go_sum_sha256':sha('go.sum'),'scope':'same test-only client for both server arms'}
with open(sys.argv[3],'x') as f:json.dump(r,f,indent=2);f.write('\n')
os.chmod(sys.argv[3],0o600)
PY
