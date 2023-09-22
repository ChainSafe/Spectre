#!/bin/bash
TESTS_TAG=v1.3.0
REPO_NAME=consensus-spec-tests
CONFIGS="general minimal"

set -eou pipefail

mkdir -p ${REPO_NAME}
for config in ${CONFIGS}
do
    wget https://github.com/ethereum/${REPO_NAME}/releases/download/${TESTS_TAG}/${config}.tar.gz
    tar -xzf ${config}.tar.gz -C ${REPO_NAME}
done
