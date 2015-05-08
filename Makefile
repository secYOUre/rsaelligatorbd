.PHONY: deps

BACKDOOREDKEY?=backdooredkey.key
RECOVEREDKEY?=recoveredkey.key
CERT?=cert.crt
SECRET?=wecantkeepthissecretamongthefewthousandsofusatHITB


all: deps

deps: distclean pyelligator python-tweetnacl

pyelligator:
	git clone --branch master --depth=1 --quiet https://github.com/secYOUre/pyelligator
	(cd pyelligator; ${MAKE} );

python-tweetnacl:
	wget http://mojzis.com/software/python-tweetnacl/python-tweetnacl-20140309.tar.bz2
	bunzip2 < python-tweetnacl-20140309.tar.bz2 | tar -xf -
	( cd python-tweetnacl-20140309; sh do );

distclean:
	rm -rf ./pyelligator
	rm -rf ./python-tweetnacl-20140309
	rm -f $(BACKDOOREDKEY)
	rm -f $(RECOVEREDKEY)
	rm -f cert.csr cert.crt

embed:
	. ./env.sh
	python ./embed.py > $(BACKDOOREDKEY)


recover:
	. ./env.sh
	python ./recover.py $(SECRET) $(CERT) > $(RECOVEREDKEY)

getcert:
	sh ./getcert.sh $(BACKDOOREDKEY)
