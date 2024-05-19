#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <uapi/linux/ptrace.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <bcc/proto.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <net/tcp.h>

#define TAGGED_TERMINAL 12345
struct tag_hdr {
  __u64   label;
  __u64   tracker;
};


BPF_HASH(tagged_pid, u32, struct tag_hdr);
// BPF_ARRAY(tagged_pid, struct tag_hdr, 65535);

BPF_HASH(tagged_port, u16, struct tag_hdr);
// BPF_ARRAY(tagged_ports, u16, 65535);

BPF_HASH(tagged_files, unsigned long, struct tag_hdr);

BPF_HASH(time, u16, u64);

BPF_HASH(currsock, u32, struct sock *);

BPF_HASH(taggedflow, u16, struct tag_hdr);



//####################################################################
//
//execve trace
//
//####################################################################

int do_ret_sys_execve(struct pt_regs *ctx)
{
    
    struct task_struct *task;
    struct tag_hdr *taghdr;
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;

    taghdr = tagged_pid.lookup(&ppid);
    if(taghdr != 0){
      tagged_pid.update(&pid, taghdr);
    } 
    
    else{
      u32 newPid = TAGGED_TERMINAL;
      struct tag_hdr defult_hdr = {.tracker=htons(1), .label=htons(1),};
      tagged_pid.update(&newPid, &defult_hdr);
    }
    return 0;
}

int syscall_clone (struct pt_regs *ctx, unsigned long flags, void *child_stack,
                void *ptid, void *ctid, struct pt_regs *regs) {
  struct task_struct *task;
  struct tag_hdr *taghdr;

  u32 pid = bpf_get_current_pid_tgid();
  task = (struct task_struct *)bpf_get_current_task();
  u32 ppid = task->parent->tgid;
  // u32 ppid = task->tgid;

  u32 child_pid = PT_REGS_RC(ctx);
  if (child_pid <= 0) {
    return 1;
  }

  taghdr = tagged_pid.lookup(&ppid);
      if(taghdr != 0){
        tagged_pid.update(&child_pid, taghdr);
      } 

  return 0;
}

//####################################################################
//
//exit tracing
//
//####################################################################

TRACEPOINT_PROBE(sched, sched_process_exit)
{
    struct task_struct *task = (typeof(task))bpf_get_current_task();

    if(task != 0){
      u32 pid = task->tgid;
      if(pid != 0)
      tagged_pid.delete(&pid);
    }
    return 0;
}


//####################################################################
//
//Incoming passive tcp tracing
//
//####################################################################



int kretprobe__inet_csk_accept(struct pt_regs *ctx){
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    if (newsk == NULL)
        return 0;
    
    u16 lport = newsk->__sk_common.skc_num;
    u16 dport = newsk->__sk_common.skc_dport;
    dport = ntohs(dport);


    struct tag_hdr * tagh;
    
    tagh = taggedflow.lookup(&dport);
    if(tagh != 0 && pid != 0){
        tagged_pid.update(&pid, tagh);       
        
    }
      
    return 0;

}

//####################################################################
//
//Outgoing connections
//
//####################################################################
int trace_tcp_v4_connect_entry(struct pt_regs *ctx, struct sock *sk, int addr_len)
{

	u32 pid = bpf_get_current_pid_tgid();
	currsock.update(&pid, &sk);
	return 0;
};

int kretprobe__inet_hash_connect(struct pt_regs * ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  int ret = PT_REGS_RC(ctx);

  struct sock ** skpp;
  skpp = currsock.lookup( & pid);
  if (skpp == 0) {
    return 0; // missed entry
  }

  if (ret != 0) {
    // failed to send SYNC packet, may not have populated
    // socket __sk_common.{skc_rcv_saddr, ...}
    currsock.delete( & pid);
    return 0;
  }

  struct task_struct *task;
  task = (struct task_struct *)bpf_get_current_task();
  u32 ppid = task->real_parent->tgid;

  // pull in details
  struct sock * skp = * skpp;
  struct inet_sock * sockp = (struct inet_sock * ) skp;
  u16 sport = sockp -> inet_sport;
  u32 dest_ip = sockp -> inet_daddr;
  sport = ntohs(sport);

    struct tag_hdr *taghdr;

      taghdr = tagged_pid.lookup(&pid);
      if(taghdr != 0){
        tagged_port.update(&sport, taghdr);
      }
	

	currsock.delete(&pid);

     return 0;
}

// int trace_udp_sendmsg(struct pt_regs *ctx)
// {
//     __u64 pid_tgid = bpf_get_current_pid_tgid();
//     struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
//     struct inet_sock *is = inet_sk(sk);
//     // only grab port 53 packets, 13568 is ntohs(53)
//     if (is->inet_dport == 13568) {
//         struct msghdr *msghdr = (struct msghdr *)PT_REGS_PARM2(ctx);
//         tbl_udp_msg_hdr.update(&pid_tgid, &msghdr);
//     }
//     bpf_trace_printk("UDP CATCH\\n");
//     return 0;
// }



//####################################################################
//
//File Create
//
//####################################################################



int trace_security_inode_create(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // struct dentry *dentry = path->dentry;
  struct qstr d_name = dentry->d_name;
   struct tag_hdr *taghdr;
  unsigned long inode_num = dir->i_ino;
  
  if (dentry == NULL)
 

  taghdr = tagged_pid.lookup(&pid);
  if(taghdr != 0){
    tagged_files.update(&inode_num, taghdr);
  } else {
    struct tag_hdr default_hdr = {.tracker=htons(1), .label=htons(1),};
    tagged_files.update(&inode_num, &default_hdr);
  }

  return 0;
}

// int trace_open(struct pt_regs *ctx, struct path*path, struct file *file){
//   struct dentry *dentry = path->dentry;

//   if (!(file->f_mode & FMODE_CREATED)) {
//         return 0;
//   }

//   unsigned long inode_num = dentry->d_inode->i_ino;
//   bpf_trace_printk("SECURITY INODE TRACE FILE INODE: %lu\\n", inode_num);

//     return 0;
// }

int trace_create(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  if (pid > 2000){
    // struct dentry *dentry = path->dentry;
    struct qstr d_name = dentry->d_name;
    if (d_name.len == 0)
        return 0;
  }
  
  return 0;
}

//####################################################################
//
//File Read
//
//####################################################################

int trace_open(struct pt_regs *ctx, struct path *path, struct file *file)
{
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  struct dentry *dentry = path->dentry;
  unsigned long inode_num = dentry->d_inode->i_ino;

  struct tag_hdr *file_taghdr;
  struct tag_hdr *process_taghdr;
  
  file_taghdr = tagged_files.lookup(&inode_num);
  process_taghdr = tagged_pid.lookup(&pid);
  if(file_taghdr != 0 && process_taghdr != 0){
    process_taghdr->tracker = file_taghdr->tracker;
    // process_taghdr->id2 = file_taghdr->id2;
    process_taghdr->label = file_taghdr->label | process_taghdr->label;
  }
  
  return 0;
}

int trace_read(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count, int is_read){
      struct tag_hdr *taghdr_file;
      struct tag_hdr *taghdr_process;
      unsigned long inode = file->f_inode->i_ino;
      
      taghdr_file = tagged_files.lookup(&inode);
      if(taghdr_file != 0){
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        taghdr_process = tagged_pid.lookup(&pid);
        if(taghdr_process != 0){
          taghdr_process->label = taghdr_process->label | taghdr_file->label;
        }
      }


      return 0;
    }


//####################################################################
//
//ingress handling
//
//####################################################################
#define IP_TCP 6


int handle_ingress(struct xdp_md *ctx){
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data, eth_copy;
    struct iphdr *iph, iph_copy;
    struct tcphdr *tcph, tcph_copy;
    struct tag_hdr *tagh, tagh_copy;
   

    if (data + sizeof(*eth) > data_end)
     return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
     return XDP_PASS;

    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
     return XDP_PASS;


    iph = data + sizeof(*eth);
    
    if (iph->protocol == IP_TCP){

    if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
       return XDP_PASS;

      tcph = data + sizeof(*eth) + sizeof(*iph);

  u16 dstport = ntohs(tcph->source);

      //0x0080 is converted to little endian 0x8000
      if(iph->frag_off & 0x0080){
      iph->frag_off =  iph->frag_off ^ 0x0080;

      
      if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) + sizeof(*tagh) > data_end)
       return XDP_PASS;

     tagh = data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph);

      



      __builtin_memcpy(&eth_copy, eth, sizeof(eth_copy));
      __builtin_memcpy(&iph_copy, iph, sizeof(iph_copy));
      __builtin_memcpy(&tcph_copy, tcph, sizeof(tcph_copy));
      __builtin_memcpy(&tagh_copy, tagh, sizeof(tagh_copy));

      u16 dest_port = ntohs(tcph->source);
      if (dest_port != 0 && tagh_copy.label != 0){
         taggedflow.update(&dest_port, &tagh_copy);
      }

      if(bpf_xdp_adjust_head(ctx, 16))
        return XDP_PASS;

      data = (void *)(long) ctx->data;
      data_end = (void *)(long) ctx->data_end;
      if(data + 1 > data_end)
        return XDP_PASS;
      
      eth = data;
      if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
      
      if (data + sizeof(*eth) + sizeof(*iph) > data_end)
      return XDP_PASS;

      iph = data + sizeof(*eth);

      if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
       return XDP_PASS;

      tcph = data + sizeof(*eth) + sizeof(*iph);

      __builtin_memcpy(eth, &eth_copy, sizeof(*eth));
      __builtin_memcpy(iph, &iph_copy, sizeof(*iph));
      __builtin_memcpy(tcph, &tcph_copy, sizeof(*tcph));

    
    return XDP_PASS;
      }
     return XDP_PASS;
    }
    return XDP_PASS;

}


//####################################################################
//
//egress handling
//
//####################################################################


#define MAX_UDP_SIZE 1480

__attribute__((__always_inline__))
static inline __u16 caltcpcsum(struct iphdr *iph, struct tcphdr *tcph, void *data_end)
{
    __u32 csum_buffer = 0;
    __u16 *buf = (void *)tcph;

    // Compute pseudo-header checksum
    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u16)iph->protocol << 8;
    unsigned short tcpLen = ntohs(iph->tot_len) - (iph->ihl<<2);
    
    csum_buffer += htons(tcpLen);

    // Compute checksum on udp header + payload
    for (int i = 0; i < MAX_UDP_SIZE; i += 2) 
    {
        if ((void *)(buf + 1) > data_end) 
        {
            break;
        }

        csum_buffer += *buf;
        buf++;
    }

    if ((void *)buf + 1 <= data_end) 
    {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    csum = ~csum;

    return csum;
}

int handle_egress(struct __sk_buff *skb){
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data, eth_copy;
    struct iphdr *iph, iph_copy;
    struct tcphdr *tcph, tcph_copy;
    struct tag_hdr *thdr, thdr_copy;


    if (data + sizeof(*eth) > data_end)
    return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return TC_ACT_OK;

    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
    return TC_ACT_OK;


    iph = data + sizeof(*eth);
    
    if (iph->protocol == IP_TCP){
      if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
        return TC_ACT_OK;

      tcph = data + sizeof(*eth) + sizeof(*iph);

      //measure packet sending latency
      // u16 sport; 
      // u16 dsport = ntohs(tcph->dest);
      // if(dsport == 0)
      // return TC_ACT_OK;
      // u64 old_ts, *tsp;
      // tsp = time.lookup(&dsport);
      // if(tsp == 0)
      // return TC_ACT_OK;
      // u64 ts = bpf_ktime_get_ns();
      // u64 new_ts = ts - *tsp;
      // bpf_trace_printk("TIME  %d\\n", new_ts);

      
      if(tcph->syn){
        u16 sport = ntohs(tcph->source);
        thdr = tagged_port.lookup(&sport);
        // bpf_trace_printk("TC EGRESS ACK \\n");
        if(thdr != 0){
          thdr_copy = *thdr;
            tagged_port.delete(&sport);

            tcph->check = 0;
            tcph->check = caltcpcsum(iph, tcph, data_end);  

          
          iph->frag_off =  iph->frag_off | 0x0080;
          // bpf_trace_printk("SKB len before  %d\\n", skb->len);
          long ret = bpf_skb_load_bytes(skb, 0, &eth_copy, sizeof(eth_copy));
          if (ret) {
            return TC_ACT_SHOT;
          }
          // bpf_trace_printk("eth len before  %d\\n", sizeof(eth_copy));
          ret = bpf_skb_load_bytes(skb, sizeof(*eth), &iph_copy, sizeof(iph_copy));
          if (ret) {
            return TC_ACT_SHOT;
          }
          // bpf_trace_printk("ip len before  %d\\n", sizeof(*iph));
          ret = bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(*iph), &tcph_copy, sizeof(tcph_copy));
          if (ret) {
            return TC_ACT_SHOT;
          }
          if (ret) {
            return TC_ACT_SHOT;
          }
          // bpf_trace_printk("tcp len before  %d\\n", sizeof(*tcph));


          // bpf_trace_printk("IP ttl before adjust  %d\\n", iph->ttl);
          ret = bpf_skb_adjust_room(skb, 16, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO);
          if (ret) {
            return TC_ACT_SHOT;
          }

          ret = bpf_skb_store_bytes(skb, 0, &eth_copy, sizeof(eth_copy), 0);
          if (ret) {
                  return TC_ACT_SHOT;
          }
          ret = bpf_skb_store_bytes(skb, sizeof(*eth), &iph_copy, sizeof(iph_copy), 0);
          if (ret) {
                  return TC_ACT_SHOT;
          }
          ret = bpf_skb_store_bytes(skb, sizeof(*eth) + sizeof(*iph), &tcph_copy, sizeof(tcph_copy), 0);
          if (ret) {
                  return TC_ACT_SHOT;
          }
          ret = bpf_skb_store_bytes(skb, sizeof(*eth) + sizeof(*iph) + sizeof(*tcph), &thdr_copy, 16, 0);
          if (ret) {
                  return TC_ACT_SHOT;
          }

          
      }   
      }
    
      return TC_ACT_OK;
    }

    return TC_ACT_OK;

}