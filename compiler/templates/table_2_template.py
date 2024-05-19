# table_action3 label -> dst_address
dst_ip_addr = struct.unpack("!L", socket.inet_aton(DST_IP))[0]
tag_label = LABEL
decision = DEC
key = table_action3.make_key([gc.KeyTuple('hdr.flowtag.tag_label',tag_label, tag_label),
                            gc.KeyTuple('hdr.ipv4.dst_addr',dst_ip_addr)])
data = table_action.make_data([gc.DataTuple('priority', 1),
                              gc.DataTuple('decision', decision)], 'SwitchIngress.table_action3')
table_action.entry_add(target, [key], [data])

# ========================================================