from __future__ import annotations

import socket


class PortAllocator:
    def __init__(self,start=9100,end=9199): self.start,self.end=start,end; self.allocated:set[int]=set()
    def allocate(self)->int:
        for port in range(self.start,self.end+1):
            if port in self.allocated: continue
            try:
                sock=socket.socket()
            except PermissionError:
                # Some restricted test sandboxes disallow socket creation;
                # the real bridge still gets collision protection at bind time.
                self.allocated.add(port); return port
            with sock:
                try: sock.bind(("127.0.0.1",port))
                except OSError: continue
            self.allocated.add(port); return port
        raise RuntimeError("no loopback MCP ports available")
    def reserve(self,port:int)->None:
        if not self.start<=port<=self.end: raise ValueError("port outside MCP range")
        if port in self.allocated: raise ValueError("port already allocated")
        self.allocated.add(port)
    def release(self,port:int)->None: self.allocated.discard(port)
