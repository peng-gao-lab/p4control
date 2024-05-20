#!/usr/bin/env python3
import ipaddress
import sys
import os
sys.path.append(os.path.expandvars('$SDE/install/lib/python3.6/site-packages/tofino/'))
from bfrt_grpc import client
import grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
import socket, struct
import netcl

#Connect to BF Runtime Server 
interface = gc.ClientInterface(grpc_addr="localhost:50052", client_id=0,device_id=0) 
print('Connected to BF Runtime Server') 
# Get the information about the running program on the bfrt server. 
bfrt_info = interface.bfrt_info_get() 
print('The target runs program ', bfrt_info.p4_name_get()) 
# Establish that you are working with this program 
interface.bind_pipeline_config(bfrt_info.p4_name_get()) 

####### You can now use BFRT CLIENT #######
target = gc.Target(device_id=0, pipe_id=0xffff)

# Policy Rules
table_action2 = bfrt_info.table_get("t_table_action2")
table_action3 = bfrt_info.table_get("t_table_action3")
table_action4 = bfrt_info.table_get("t_table_action4")
# table_action5 = bfrt_info.table_get("t_table_action5")

# Other tables
forward_table = bfrt_info.table_get("table_forward")
table_dst_tag_label = bfrt_info.table_get("table_dst_tag_label")
table_dec = bfrt_info.table_get("table_dec")

# Add by request (digest)
table_conn = bfrt_info.table_get("table_conn")

netcl.insert_rules()


# table_dec
key = table_dec.make_key([gc.KeyTuple('ig_md.decision', 0)])
data = table_dec.make_data([], 'NoAction')
table_dec.entry_add(target, [key], [data])

key = table_dec.make_key([gc.KeyTuple('ig_md.decision', 1)])
data = table_dec.make_data([], 'SwitchIngress.miss')
table_dec.entry_add(target, [key], [data])

key = table_dec.make_key([gc.KeyTuple('ig_md.decision', 2)])
data = table_dec.make_data([], 'SwitchIngress.modify')
table_dec.entry_add(target, [key], [data])

key = table_dec.make_key([gc.KeyTuple('ig_md.decision', 3)])
data = table_dec.make_data([gc.DataTuple('egress_port', 62)], 'SwitchIngress.reroute')
table_dec.entry_add(target, [key], [data])

# ====================================
#forward_table
# Define the key
dst_ip_addr = 0x0a000003
key = forward_table.make_key([gc.KeyTuple('hdr.ipv4.dst_addr',dst_ip_addr)])
# Define the data for the matched key.
dst_port= 62
data = forward_table.make_data([gc.DataTuple('dst_port', dst_port)], 'SwitchIngress.route')
# Add the entry to the table
forward_table.entry_add(target, [key], [data])

# Define the key
dst_ip_addr = 0x0a000002
key = forward_table.make_key([gc.KeyTuple('hdr.ipv4.dst_addr',dst_ip_addr)])
dst_port= 61
data = forward_table.make_data([gc.DataTuple('dst_port', dst_port)], 'SwitchIngress.route')
# Add the entry to the table
forward_table.entry_add(target, [key], [data])

# Define the key
dst_ip_addr = 0x0a000001
key = forward_table.make_key([gc.KeyTuple('hdr.ipv4.dst_addr',dst_ip_addr)])
# Define the data for the matched key.
dst_port= 60
data = forward_table.make_data([gc.DataTuple('dst_port', dst_port)], 'SwitchIngress.route')
# Add the entry to the table
forward_table.entry_add(target, [key], [data])

# =========================================================
# table_dst_tag_label

# Define the key
dst_ip_addr = 0x0a000001
key = table_dst_tag_label.make_key([gc.KeyTuple('hdr.ipv4.dst_addr', value=dst_ip_addr)])
# Define the data for the matched key.
dst_label_tag = 0x01
data = table_dst_tag_label.make_data([gc.DataTuple('dst_label', dst_label_tag)], 'SwitchIngress.get_dst_label')
# Add the entry to the table
table_dst_tag_label.entry_add(target, [key], [data])

# Define the key
dst_ip_addr = 0x0a000002
key = table_dst_tag_label.make_key([gc.KeyTuple('hdr.ipv4.dst_addr', value=dst_ip_addr)])
# Define the data for the matched key.
dst_label_tag = 0x02
data = table_dst_tag_label.make_data([gc.DataTuple('dst_label', dst_label_tag)], 'SwitchIngress.get_dst_label')
# Add the entry to the table
table_dst_tag_label.entry_add(target, [key], [data])

# Define the key
dst_ip_addr = 0x0a000003
key = table_dst_tag_label.make_key([gc.KeyTuple('hdr.ipv4.dst_addr', value=dst_ip_addr)])
# Define the data for the matched key.
dst_label_tag = 0x04
data = table_dst_tag_label.make_data([gc.DataTuple('dst_label', dst_label_tag)], 'SwitchIngress.get_dst_label')
# Add the entry to the table
table_dst_tag_label.entry_add(target, [key], [data])

# =========================================================


print("DONE")

def add_table_conn(src_addr, dst_addr, src_port, dst_port, decision):
  key = table_conn.make_key([gc.KeyTuple('hdr.ipv4.src_addr', value=src_addr), gc.KeyTuple('hdr.ipv4.dst_addr', value=dst_addr), gc.KeyTuple('hdr.tcp.src_port', value=src_port), gc.KeyTuple('hdr.tcp.dst_port', value=dst_port)])
  # Define the data for the matched key.
  data = table_conn.make_data([gc.DataTuple('decision', decision)], 'SwitchIngress.enforce_dec')
  # Add the entry to the table
  table_conn.entry_add(target, [key], [data])
  print("ADDED a new entry in table_conn")

def handle_pkt(data_dict):
    src_addr = data_dict['src_addr']
    dst_addr = data_dict['dst_addr']
    src_port = data_dict['src_port']
    dst_port = data_dict['dst_port']
    tag_id = data_dict['tag_id']
    digest_op = data_dict['digest_op']
    tag_label = data_dict['tag_label']
    decision = data_dict['decision']
    block_dst_addr = data_dict['block_dst_addr']
    tag_decision = data_dict['tag_decision']

    if(data_dict['digest_op'] == 1): #DIGEST_ADD_CONN
      print("RECEIVED DIGEST_ADD_CONN | Decision is ", data_dict['decision'])
      add_table_conn(data_dict['src_addr'], data_dict['dst_addr'], data_dict['src_port'], data_dict['dst_port'], data_dict['decision'])

while True:
    try:
        msg = interface.digest_get(timeout=0.1)
        if msg is not None:
            # print(msg)
            learn_filter = bfrt_info.learn_get("my_digest")
            data_list = learn_filter.make_data_list(msg)
            data_dict = data_list[0].to_dict()
            handle_pkt(data_dict)
    except:
        pass
