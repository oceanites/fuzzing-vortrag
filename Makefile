pdf:
	patch -i README.patch -o README-pandoc.md README.md
	pandoc README-pandoc.md -f markdown+yaml_metadata_block --pdf-engine=xelatex -t latex -V lang=de -o README.pdf
all: pdf
