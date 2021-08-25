#!/bin/bash -e

sig="test.sig"

"$sbsign" --cert "$cert" --key "$key" --detached --output $sig "$image" || exit 1
"$sbverify" --cert "$cert" --detached $sig "$image" || exit 1
"$sbverify" --cert "$intcert" --detached $sig "$image" || exit 1
# should fail because no intermediate
"$sbverify" --cert "$cacert" --detached $sig "$image" && exit 1

# now make sure everything succeeds with the intermediate added
"$sbsign" --cert "$cert" --key "$key" --addcert "$intcert" --detached --output $sig "$image" || exit 1
"$sbverify" --cert "$cert" --detached $sig "$image" || exit 1
"$sbverify" --cert "$intcert" --detached $sig "$image" || exit 1
"$sbverify" --cert "$cacert" --detached $sig "$image" || exit 1

exit 0
