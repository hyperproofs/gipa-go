#!/usr/bin/env bash
set -e
shopt -s expand_aliases
alias time='date; time'

scriptdir=$(cd $(dirname $0); pwd -P)
sourcedir=$(cd $scriptdir/..; pwd -P)

time go test -v ./gipa ./gipakzg -bench=. -run=Bench -benchtime 2x -timeout 240m
time go test -v ./batch ./batchplain -bench=. -run=Bench -benchtime 2x -timeout 240m
# time go test -v ./utils -bench=. -run=Bench -benchtime 4x -timeout 240m
# time go test -v ./gipa -bench=. -run=Bench -benchtime 4x -timeout 240m
# time go test -v ./gipakzg -bench=. -run=Bench -benchtime 4x -timeout 240m
# time go test -v ./batchplain -bench=. -run=Bench -benchtime 2x -timeout 240m
# time go test -v ./batch -bench=. -run=Bench -benchtime 2x -timeout 240m
# time go test -v ./... -bench=. -run=Bench -benchtime 4x -timeout 240m
# time go test -v ./... -bench=. -benchtime 4x -timeout 240m
