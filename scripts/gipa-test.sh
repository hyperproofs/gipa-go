#!/usr/bin/env bash
set -e
shopt -s expand_aliases
alias time='date; time'

scriptdir=$(cd $(dirname $0); pwd -P)
sourcedir=$(cd $scriptdir/..; pwd -P)

time go test -v ./...
# time go test -v ./utils
# time go test -v ./cm
# time go test -v ./gipa
# time go test -v ./gipakzg
# time go test -v ./utils ./cm ./gipa ./gipakzg
# time go test -v ./batch
# time go test -v ./batchplain
