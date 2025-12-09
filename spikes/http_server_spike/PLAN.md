# OUTLINE
- MAKE CLIENT FIRST 
- Complete the write functionality over her than move on to server with read .... loop back after that
- Support read , transfer-chunking , https
- We need support for polling , sse as well for streaming stuff ...
# CLIENT:
- request -> http header -> content write -> send
- connect -> session -> connection -> ... above send function
