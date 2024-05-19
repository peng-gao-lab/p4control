netcl:
	bison -d netcl.y
	flex netcl.l
	g++ netcl.tab.c lex.yy.c -ll -o ./netcl-compile --std=c++0x

clean:
	rm -rf netcl.tab.c netcl.tab.h lex.yy.c
	rm -rf netcl-compile netcl
