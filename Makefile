SERVER:=server.h
CLIENT:=client
GEN_CLIENT=$(CLIENT)$(EXEC)
EXE_CLIENT=./$(GEN_CLIENT)
test_server:
	cd src; \
	g++ -g -fsanitize=address server.cpp -o servero -lsqlite3 ; \
	./servero
test_client:
	cd src; \
	g++ -g -fsanitize=address client.cpp -o $(GEN_CLIENT) ; \
	$(EXE_CLIENT)
gdb_test_client:
	cd src; \
	g++ -g client.cpp -o $(GEN_CLIENT) ; \
	gdb $(EXE_CLIENT)
clean_exe_files:
	cd src; \



