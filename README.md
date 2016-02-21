# DNSManip
Proof of concept program, do not actually use it

For windows with WinPcap
## Concept
  Computer 1 sends dns request to DNS server

    Computer 1      Computer 2                          DNS server
        |               |                                    |
    ------[->]---------------------------- Router ----------------
        packet   
  
  Computer 2 sends dns answer to computer 1 as if it were sent from the dns server routed through the router


    Computer 1      Computer 2                          DNS server
        |               |                                    |
    -----------[<-]----------------------- Router -[<-]---------------
        packet as if from dns server             real packet
        
  Computer 1 will try to connect to fake ip-address
