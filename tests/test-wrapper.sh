#!/bin/bash

# set a few global variables that may be used by the test
basedir=$(cd $srcdir && pwd)
datadir=$(pwd)
bindir="$datadir/../src"

sbsign=$bindir/sbsign
sbverify=$bindir/sbverify
sbattach=$bindir/sbattach

key="$datadir/private-key.rsa"
cert="$datadir/public-cert.pem"
intkey="$datadir/int-key.ec"
intcert="$datadir/int-cert.pem"
cakey="$datadir/ca-key.ec"
cacert="$datadir/ca-cert.pem"

export basedir datadir bindir sbsign sbverify sbattach key cert intkey intcert cakey cacert

# 'test' needs to be an absolute path, as we will cd to a temporary
# directory before running the test
test="$PWD/$1"
rc=0

function run_test()
{
	test="$1"

	# image depends on the test arch
	image="$datadir/test.pecoff"
	export image

	# create the temporary directory...
	tempdir=$(mktemp --directory)

	# ... and run the test in it.
	( cd "$tempdir";  $test )

	if [ $? -ne 0 ]
	then
		echo "test $(basename $test) failed on arch $arch"
		echo
		rc=1
	fi

	rm -rf "$tempdir"
}

# run test on all available arches
for arch in $TEST_ARCHES
do
	run_test $test
done

exit $rc
