#!/bin/bash -e

signed="test.signed"

"$sbsign" --cert "$cert" --key "$key" --output "$signed" "$image" || exit 1
"$sbverify" --cert "$cert" "$signed" || exit 1
"$sbverify" --cert "$intcert" "$signed" || exit 1
# there's no intermediate cert in the image so it can't chain to the ca which
# is why this should fail
"$sbverify" --cert "$cacert" "$signed" && exit 1

# now add the intermediates and each level should succeed
"$sbsign" --cert "$cert" --addcert "$intcert" --key "$key" --output "$signed" "$image" || exit 1
"$sbverify" --cert "$cert" "$signed" || exit 1
"$sbverify" --cert "$intcert" "$signed" || exit 1
"$sbverify" --cert "$cacert" "$signed" || exit 1

