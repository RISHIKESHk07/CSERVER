# OVERLY_ENGINEERED_GAME_NETWORK_LAYER_FOR_NOOBS(needs to be adapted to unity model latter on .... sadly life sucks ... )
## IDEA:
- Make a server which accepts all messages and logs to single window for people to see and use a persistent db for storing 
- Make a client to push messages and then accept messages
- Manage resources of network , like see current users , history of logs , disconnect users manually etc
- Server & client have a single q for processing and client has a single outgoing q for messages and throttling control 
- Needs to SUPPORT HTTP 1.0 cloonections and websocket connections as well .... hopefully
## EXTRA_STUFF_WHICH_NEED_TO_DO:
- P2P connection option .. insane rn ... bittorrent protocol is insane though
- Send compressed images .. dreaming of it rn
- Checkout XMPP & WebRTC for enhancing .... life sucks here rn 
## TECH_STACK
- ASIO FOR NETWORKING
- NCURSES FOR THE UI
- GDB debugger
## PROGRESS
-[x] Setup a repo
-[x] GOT the message layer to work with my nasty message encoding
-[] Need to read tiny web server & simple web server for a http server spike and impl thread pools , db connection pools , and then websocket protocol impl as well.
## REFERENCE&NOTES 
### TINY_WEB_SERVER
- Need to read the thread pool impl & the low level impl of the epoll/proactor , and figure out webbench benchmarks 
### Simple_web_server
- Need to figure out the http parser and connection management here , add the thread safe annotations as well good practice for race cond debug


