all: 
	gcc -Wall test_cfg.c cfg.c -o test_cfg -ldisasm -lbfd
	gcc -Wall sample.c -o sample

test:
	./test_cfg sample
	dot -Tps graph.dot -o graph.ps
