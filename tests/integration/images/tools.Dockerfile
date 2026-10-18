# Test-only helper: nftables (applies the generated ruleset), xfs tools, curl.
FROM alpine:3.20
RUN apk add --no-cache nftables xfsprogs xfsprogs-extra util-linux curl e2fsprogs coreutils
