
AUTOMAKE_OPTIONS = parallel-tests

test_key = private-key.rsa
test_cert = public-cert.pem
ca_key = ca-key.ec
ca_cert = ca-cert.pem
int_key = int-key.ec
int_cert = int-cert.pem
test_arches = $(EFI_ARCH)

check_PROGRAMS = test.pecoff

# override the automake rule to say we build from .elf files
test.pecoff$(EXEEXT): test.elf

if TEST_BINARY_FORMAT
EFILDFLAGS = --defsym=EFI_SUBSYSTEM=0x0a
FORMAT = -O binary
else
FORMAT = --target=efi-app-$(EFI_ARCH)
endif
check_DATA = $(test_key) $(test_cert)
check_SCRIPTS = test-wrapper.sh

.elf.pecoff:
	echo "TEST ARCHES $(test_arches) TEST_COMPAT=$(TEST_COMPAT_FALSE)"
	$(OBJCOPY) -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym  -j .rel \
		-j .rela -j .reloc \
		$(FORMAT) $^ $@

.$(OBJEXT).elf:
	$(LD) $(EFILDFLAGS) -nostdlib -L /usr/lib -L /usr/lib64 -L $(CRTPATH) -shared -Bsymbolic $(CRTPATH)/crt0-efi-$(EFI_ARCH).o -T elf_$(EFI_ARCH)_efi.lds $< -o $@ -lefi -lgnuefi

AM_CFLAGS=-fpic -I/usr/include/efi -I/usr/include/efi/$(EFI_ARCH)

%.rsa: Makefile
	openssl genrsa -out $@ 2048

%.ec: Makefile
	openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:prime256v1 -out $@

$(ca_cert): $(ca_key) Makefile
	openssl req -x509 -days 1 -sha256 -subj '/CN=CA Key/' -new -key $< -out $@

$(int_cert): $(int_key) $(ca_cert) Makefile
	openssl req -new -subj '/CN=Intermediate Certificate/' -key $< -out tmp.req
	echo -e "[ca]\nbasicConstraints = critical, CA:true\n" > ca.cnf
	openssl x509 -req -sha256 -CA $(ca_cert) -CAkey $(ca_key) -in tmp.req -set_serial 1 -days 1 -extfile ca.cnf -extensions ca -out $@
	-rm -f tmp.req ca.cnf

$(test_cert): $(test_key) $(int_cert) Makefile
	openssl req -new -subj '/CN=Signer Certificate/' -key $< -out tmp.req
	openssl x509 -req -sha256 -CA $(int_cert) -CAkey $(int_key) -in tmp.req -set_serial 1 -days 1 -out $@
	-rm -f tmp.req

TESTS = sign-verify.sh \
	sign-verify-detached.sh \
	sign-detach-verify.sh \
	sign-attach-verify.sh \
	sign-missing-image.sh \
	sign-missing-cert.sh \
	sign-missing-key.sh \
	verify-missing-image.sh \
	verify-missing-cert.sh \
	sign-invalidattach-verify.sh \
	resign-warning.sh \
	reattach-warning.sh

if !TEST_BINARY_FORMAT
##
# These tests involve objdump which will fail because the format
# is not recognised. Someone needs to fix arm bfd to add efi
##
TESTS +=	cert-table-header.sh \
		detach-remove.sh
endif


TEST_EXTENSIONS = .sh
AM_TESTS_ENVIRONMENT = TEST_ARCHES='$(test_arches)'; export TEST_ARCHES;
SH_LOG_COMPILER = $(srcdir)/test-wrapper.sh

EXTRA_DIST = test.S $(TESTS) $(check_SCRIPTS)
CLEANFILES = $(test_key) $(test_cert) $(int_key) $(int_cert) $(ca_key) \
	$(ca_cert)
