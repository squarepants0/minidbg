minidbg: linenoise/linenoise.c ./debugger.c ./breakpoint.c ./utils.c ./main.c ./disassemble.c ./tpl/src/tpl.c
	gcc linenoise/linenoise.c ./debugger.c ./breakpoint.c ./utils.c ./main.c ./disassemble.c ./tpl/src/tpl.c -g  -o minidbg -lcapstone

reader: ./tpl/src/tpl.c ./snapreader.c
	gcc ./tpl/src/tpl.c ./snapreader.c -g -o reader

runer: ./tpl/src/tpl.c ./runer.c
	gcc ./tpl/src/tpl.c ./runer.c -g -o runer -lunicorn

clean: 
	rm minidbg
