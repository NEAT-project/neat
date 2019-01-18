txtfiles := $(patsubst %.xml,%.txt,$(wildcard draft-*.xml))
htmlfiles := $(patsubst %.xml,%.html,$(wildcard draft-*.xml))


all:   $(htmlfiles) $(txtfiles)


references:
	bibtexconv ~/src/papers/Referenzarchiv.bib -non-interactive -export-to-separate-xmls=reference.


$(txtfiles):	%.txt: %.xml
	xml2rfc $< $@ --text
	sed -i -e "s/&#263;/c/g" $@
	idnits $@

$(htmlfiles):	%.html: %.xml
	xml2rfc $< $@ --html


clean:
	rm -f *.txt *.html
