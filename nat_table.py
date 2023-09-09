class TableEntry:
    def __init__(self, ip_src, port_src, ip_dst, port_dst, protocol):
        self.ip_src = ip_src
        self.port_src = port_src
        self.ip_dst = ip_dst
        self.port_dst = port_dst
        self.protocol = protocol

    def __eq__(self, other):
        if not isinstance(other, TableEntry):
            return False
        
        return self.ip_src == other.ip_src and self.port_src == other.port_src \
            and self.ip_dst == other.ip_dst and self.port_dst == other.port_dst \
            and self.protocol == other.protocol 

    def show(self):
        print(f'Src: {self.ip_src}, {self.port_src} -> {self.protocol} {self.ip_dst} {self.port_dst}')

class NatTable:

    def __init__(self):
        self.table = []

    def add_entry(self, new_entry):
        if not self.has_entry(new_entry):
            self.table.append(new_entry)

    def has_entry(self, new_entry):
        for e in self.table:
            if e == new_entry:
                return True
        return False

    def find_entry(self, server_port, host_port):
        for e in self.table:
            if e.port_src == host_port and e.port_dst == server_port:
                return e
        return None
    
    def list_entries(self):
        print("\nNAT:\n")
        for e in self.table:
            e.show()
