#!/usr/bin/env bash
set -o errexit -o pipefail -o nounset -o xtrace

main() {
  local os arch suffix server_pid
  os=$(go env GOOS)
  arch=$(go env GOARCH)
  suffix=$([[ ${os} == "windows" ]] && echo ".exe" || echo "")

  "bin/${BIN}_${os}_${arch}${suffix}" &
  server_pid=$!
  sleep 3

  cat ../vault-audit.log | nc -c 127.0.0.1 9090
  curl --silent 127.0.0.1:9090/metrics | grep "vaultaudit"

  kill "${server_pid}"
}

main
