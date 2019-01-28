tex:
	pandoc README.md -f markdown --pdf-engine=xelatex -t latex -V lang=de -o README.tex
pdf:
	pandoc README.md -f markdown --pdf-engine=xelatex -t latex -V lang=de -o README.pdf
all: tex pdf
