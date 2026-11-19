#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cert_dir=$(mktemp -d "${TMPDIR:-/tmp}/oidc4rs-interop.XXXXXXXX")
INTEROP_CERT_DIR=$(cd "$cert_dir" && pwd -P)
export INTEROP_CERT_DIR
project="oidc4rs-interop-$$"

compose() {
    docker compose --file "$here/compose.yaml" --project-name "$project" "$@"
}

cleanup() {
    compose down --remove-orphans --rmi local || true
    rm -rf -- "$cert_dir"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

openssl req -new -x509 -nodes -newkey rsa:2048 -days 2 \
    -config "$here/tls.cnf" -extensions ca_extensions -subj '/CN=oidc4rs interop CA' \
    -keyout "$cert_dir/ca.key" -out "$cert_dir/ca.crt"
openssl req -new -nodes -newkey rsa:2048 -config "$here/tls.cnf" -subj '/CN=keycloak' \
    -keyout "$cert_dir/server.key" -out "$cert_dir/server.csr"
openssl x509 -req -days 2 -CAcreateserial -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" \
    -in "$cert_dir/server.csr" -out "$cert_dir/server.crt" \
    -extfile "$here/tls.cnf" -extensions server_extensions
chmod a+r "$cert_dir/server.key" "$cert_dir/server.crt" "$cert_dir/ca.crt"

if compose up --build --wait --wait-timeout 120 rp && compose run --build --rm browser; then
    exit 0
else
    result=$?
    compose logs keycloak rp || true
    exit "$result"
fi