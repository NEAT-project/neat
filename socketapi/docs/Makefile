OUTDIR    := Output
xmlfiles  := $(wildcard draft-*.xml)
txtfiles  := $(patsubst %.xml,$(OUTDIR)/%.txt,$(xmlfiles))
htmlfiles := $(patsubst %.xml,$(OUTDIR)/%.html,$(xmlfiles))

.PHONY: all references format clean


all: $(txtfiles) $(htmlfiles)


references:
	bibtexconv ~/src/papers/Referenzarchiv.bib --non-interactive --export-to-separate-xmls=Output/reference.

format:
	./format-id -R ~/public_html/bibxml/ $(xmlfiles)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/%.txt $(OUTDIR)/%.html: %.xml | $(OUTDIR)
	@echo "Processing $<"
	@xml2rfc $< --v3 --text --html -p $(OUTDIR) >$(OUTDIR)/$*.log

clean:
	rm -rf $(OUTDIR)
