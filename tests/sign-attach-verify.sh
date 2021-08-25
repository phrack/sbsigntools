#!/bin/bash -e

sig="test.sig"
signed="test.signed"

"$sbsign" --cert "$cert" --key "$key" --detached --output "$sig" "$image" || exit 1
cp "$image" "$signed" || exit 1
"$sbattach" --attach "$sig" "$signed" || exit 1
"$sbverify" --cert "$cert" "$signed" || exit 1
"$sbverify" --cert "$intcert" "$signed" || exit 1
# there's no intermediate cert in the image so it can't chain to the ca which
# is why this should fail
"$sbverify" --cert "$cacert" "$signed" && exit 1

# now add intermediates
"$sbsign" --cert "$cert" --key "$key" --addcert "$intcert" --detached --output "$sig" "$image" || exit 1
cp "$image" "$signed" || exit 1
"$sbattach" --attach "$sig" "$signed" || exit 1
"$sbverify" --cert "$cert" "$signed" || exit 1
"$sbverify" --cert "$intcert" "$signed" || exit 1
"$sbverify" --cert "$cacert" "$signed" || exit 1
