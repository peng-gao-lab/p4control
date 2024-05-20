def insert_rules:
    # =========================================================
    # table_action2 Declassification

    # Define the key
    src_ip_addr = 0x0a000002
    dst_ip_addr = 0x0a000003
    key = table_action2.make_key([gc.KeyTuple('hdr.ipv4.dst_addr',dst_ip_addr),
                                gc.KeyTuple('hdr.ipv4.src_addr',src_ip_addr)])
    data = table_action2.make_data([gc.DataTuple('priority', 9),
                                  gc.DataTuple('decision', 0),
                                  gc.DataTuple('declassify_label', 0xFE)], 'SwitchIngress.table_action2')
    table_action2.entry_add(target, [key], [data])


    # ========================================================
    # table_action3 label -> dst_address
    dst_ip_addr = struct.unpack("!L", socket.inet_aton("10.0.0.3"))[0]
    key = table_action3.make_key([gc.KeyTuple('hdr.flowtag.tag_label',0x01, 0x01),
                                gc.KeyTuple('hdr.ipv4.dst_addr',dst_ip_addr)])
    data = table_action3.make_data([gc.DataTuple('priority', 1),
                                  gc.DataTuple('decision', 2)], 'SwitchIngress.table_action3')
    table_action3.entry_add(target, [key], [data])

    # ========================================================
    # table_action4 
    key = table_action4.make_key([gc.KeyTuple('hdr.ipv4.dst_addr',0x0a000003),
                                gc.KeyTuple('hdr.flowtag_id.tag_id',1)])
    data = table_action4.make_data([gc.DataTuple('priority', 5),
                                  gc.DataTuple('decision', 2)], 'SwitchIngress.table_action4')
    table_action4.entry_add(target, [key], [data])

    # ========================================================