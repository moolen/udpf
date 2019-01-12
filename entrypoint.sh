#!/bin/bash
set -euxo pipefail
: "${IFACE:="eth0"}"

error() {
    echo "${1}"
    exit 1
}

[ -z ${TARGET} ] && error "\$TARGET is not defined"

cd /go/src/github.com/moolen/udpf
./udpf -target "${TARGET}" -iface "${IFACE}"
