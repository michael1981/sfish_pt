#TRUSTED 41d2e01038a11b558d8e1f81b307d3c45c7b1b466b40a99f34771b6822f4e9fcbdafcfaef2304e63e9e8487269e4fe07e68773c513a2282a3a4169446bc09baa09d0051450f4485fb9e451de3a9b1d6a76345d8ed0cbd30a342eddfba0971ae093eeece2f9e3510b2837f201d335234ef14761a809f090a0534ae68e0dcfa5c9be34f70ec98e3b15291fabe769f8e7c402a1e48bde7033d9fa1d3437e278ac2f8d71332be99d257fc392b23ac2a8f4a4bd627104ca1a510ed4ad4e82497a05099999c071cf7bb3f37a0b04739fcc35bdd629ec1bbcee2a6d4f6c439d47848972f8d457e9634746b721bfe64494d42e0de2f57f197ee022f0a8ca57f80c83b1cb02953ded2951d970b5876bf1d4fbff1d61d7c0ca7ce5933fd0d6043d78824c11a15a2f810ee57d5d89971b66781de47ffde5577894e60f4d2cf84ea645f338a5c443622db93bbd472b1b57be35dbb54a0626ec21674955d32d9f0ffd7ff2a58c0ae5af973488e0480b38343949006d7671fb8517b9aac6ba4a3286a260082fab66728bd07deb6639efbff72970f2005cc2a008c09b45902fbd05875201ca16989e4ebdb251dc167670192249941ca862494b98c928ddc7823975caf360e22cd7b686e5f507ab77f6c37aeca84967bfb9feefc326549c24bce90188c5e67a6bc1fbb944838915479d028f6ef4e09ff9d73a11358b8df369e69c0b4f9dfa81ec8f
#
#
# (C) Tenable Network Security, Inc.
# @NOGPL@
#
#
# This file is used by the functions start_denial()/end_denial(). Do not edit it !!
#


# 
# Utilities
#
function mkbyte()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return raw_string(l & 0xff);
}

function mkword()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return  raw_string((l >> 8) & 0xFF, l & 0xFF);
}

function mkipaddr()
{
 local_var ip;
 local_var str;

 ip = _FCT_ANON_ARGS[0];
 str = split(ip, sep:'.', keep:FALSE);
 return raw_string(int(str[0]), int(str[1]), int(str[2]), int(str[3])); 
}



 

function arp_ping()
{
 local_var broadcast, macaddr, ethernet, arp, r, i, srcip, dstmac, t1, t2;

 broadcast = crap(data:raw_string(0xff), length:6);
 macaddr   = get_local_mac_addr();

 if ( ! macaddr ) return 0;  # Not an ethernet interface

 arp       = mkword(0x0806); 


 ethernet = broadcast + macaddr + arp;

 arp      = ethernet +              			# Ethernet
           mkword(0x0001) +        			# Hardware Type
           mkword(0x0800) +        			# Protocol Type
           mkbyte(0x06)   +        			# Hardware Size
           mkbyte(0x04)   +        			# Protocol Size
           mkword(0x0001) +        			# Opcode (Request)
           macaddr        +        			# Sender mac addr
           mkipaddr(this_host()) + 			# Sender IP addr
           crap(data:raw_string(0), length:6) + 	# Target Mac Addr
           mkipaddr(get_host_ip());

 t1 = gettimeofday();
 for ( i = 0 ; i < 3 ; i ++ )
{
 r = inject_packet(packet:arp, filter:"arp and arp[7] = 2 and src host " + get_host_ip(), timeout:1);
 if ( r && strlen(r) > 31 ) 
  {
  t2 = gettimeofday();
  srcip = substr(r, 28, 31);
  if ( srcip == mkipaddr(get_host_ip() ) )
    return 1;
  }
}
 return 0;
}


if(islocalhost()) return 1;


if ( islocalnet() && !TARGET_IS_IPV6 ) 
  return arp_ping();

if (tcp_ping()) return 1;

# Try ICMP ping
pfilter = "src host " + get_host_ip()+ " and dst host " + this_host() +
	 " and ( icmp and icmp[0]=0 or tcp )";
# and ((tcp[13] & 23) == 18)

ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:0,ip_len:20,
     		       ip_p:IPPROTO_ICMP, ip_id: rand() % 65536, ip_ttl:0x40,
 		       ip_src:this_host());
icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
 			    icmp_seq: rand() % 65536, icmp_id: rand() % 65535);

for (i = 1; i < 4; i ++)
{
 r =  send_packet(icmp, pcap_active:TRUE, pcap_filter: pfilter, pcap_timeout: i);
 if (r) return 1;
}

# Try again TCP
try_ports_l = make_list(22, 23, 53, 79, 111, 113, 135, 139, 143, 264, 389, 443, 445, 497, 515, 548, 993, 1025, 1027, 1454, 1723, 1917, 1028, 1029, 2869, 3389, 5000, 6000, 9100);
 foreach port (try_ports_l)
  if (get_port_state(port))
  {
   ip = forge_ip_packet(ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 40,
                        ip_id : rand() % 65535,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 64,
                        ip_off : 0,
			ip_src : this_host());
    tcp = forge_tcp_packet(ip       : ip,
                           th_sport : 1024 + rand() % 64512,
                           th_dport : port,
                           th_flags : TH_SYN,
                           th_seq   : rand(),
                           th_ack   : 0,
                           th_x2    : 0,
                           th_off   : 5,
                           th_win   : 512);
    r = send_packet(tcp, pcap_active:TRUE, pcap_filter: pfilter, pcap_timeout: 0);
    if (r) return 1;
  }

to = int(get_preference("checks_read_timeout")); if (! to) to = 5;
r = pcap_next(pcap_filter: pfilter, timeout: to);
if (r) return 1;

# No answer - this file MUST end with "return TRUE / FALSE"
return 0;

