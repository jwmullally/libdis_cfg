all:
	gcc -Wall -g test_cfg.c cfg.c -o test_cfg -ldisasm -lbfd
	gcc -Wall -g sample.c -o sample

test:
	./test_cfg sample
	dot -Tpdf graph.simple.dot -o graph.simple.pdf
	dot -Tpdf graph.dot -o graph.pdf
	dot -Tpng graph.dot -o graph.png
