
class NatEntry:
    def __init__(self, src_ip, src_port, dest_ip, dest_port, protocol):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.protocol = protocol

    def __eq__(self, other):
        if not isinstance(other, NatEntry):
            return False
        return (self.src_ip, self.src_port, self.dest_ip, self.dest_port, self.protocol) == \
               (other.src_ip, other.src_port, other.dest_ip, other.dest_port, other.protocol)
    
    def match_src(self, ip, port, protocol):
        return self.src_ip == ip and self.src_port == port and self.protocol == protocol

    def match_dest(self, ip, port, protocol):
        return self.dest_ip == ip and self.dest_port == port and self.protocol == protocol

class NatTable:
    def __init__(self):
        self.table = []

    def add_entry(self, entry : NatEntry):
        if NatTable.has_entry(self, entry):
            return 
        self.table.append(entry)

    def has_entry(self, new_entry):
        for entry in self.table:
            if entry == new_entry:
                return True
        return False

    def response_translate(self, ip, port, protocol):
        for entry in self.table:
            if NatEntry.match_src(entry, ip, port, protocol):
                return entry
        return None

    def list_entries(self):
        print("\n## NAT table:")
        for entry in self.table:
            print(f"Source: {entry.src_ip}:{entry.src_port} -> Destination: {entry.dest_ip}:{entry.dest_port}, Protocol: {entry.protocol}")
        print('\n')
