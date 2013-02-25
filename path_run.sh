#!/bin/bash

cwd=$(dirname $0)

export PYTHONPATH="${HOME}/Documents/Source/pudb:${cwd}/src:${cwd}/../pyoidc/src"
export PATH="${cwd}/script:${PATH}"

$@
