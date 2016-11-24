#TRUSTED 6008e4f1f5ce9ee29e0715e1f589de23224dd1e2f6a6eded409aad642ede6b6689795cc71192672852b517be8c1c5995053d28647df2f7b9790ccce62381386d7b342ae732092aa70632a21a5e31c620757c0e1df75cd74a95db8cfa9fcb63d080ffd28c747f8504f416cb17fe2963e8f40fd2472f4ad2092b070bb4a85f76dbf5b2bbc58b755fd8fd3db5e3b4420bc0c039eab6ddde5101fc6be2febebfef0b25de08a11ae4685460eef13fd1191870fc28e11ac4aff518676868075a9d2b2d1fddd35dbf3fad96fe765a26a06dbaef07e744c8c2e760320cffc59b844fb78cbb8e03907c6a7dc477b51b7f65017202e50abba2ccbe407c9e4e63848eecddf7c095640eb9a7b803cd37b736bf4492924723589e093ea2116a1c001d47986d564e5802ee6faf8d1857f5fbe3a0421ab1d39a88355580fde4b4c0211fb91dd600e3f811a436a338cfec4bca33c0c5e0468d5519560bcda9a39e90867667829b5074754e2105ca4fbbc82bf7e53e35bf2e568b341876662a252985a57ab3e0023eaa3c951c6a02e733f3e2fc1304c7f59a54c7367891a9ff4abd2e9ad22b459d683b4f184e7b32f808c393a89b5ea945ef5671901d426b52f0bb4b8f8f17064afb031342bf64df8c4e35b765509f7cf0e53e090c568b6882e0124e8379b06de15b8bada8a3511038108596e1a2fd9f44fe456325d22937e38cf5561a766a04a1ca
#
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
#
# @NOGPL@
#
#

#----------------------------------------------------------------------------#
# IP									     #
#----------------------------------------------------------------------------#


#
# Definition of the IP structure
#

ip6_sizes = make_array(
		"ip6_vfc",  8,
		"ip6_flow",   24,
		"ip6_plen",   16,
		"ip6_nxt",     8,
		"ip6_hlim",    8,
		"ip6_src",128,
		"ip6_dst",128);

ip6_struct = make_list("ip6_vfc", 
		      "ip6_class", 
		      "ip6_flow", 
		      "ip6_plen", 
		      "ip6_nxt", 
		      "ip6_hlim", 
		      "ip6_src", 
		      "ip6_dst");





#
# Set any IP element
#

function ip6_set(ip6, ip6_vfc, ip6_flow, ip6_plen, ip6_nxt, ip6_hlim, ip6_src, ip6_dst)
{
 local_var head,  t;
 local_var ret;

 if ( ip6["type"] != "ip6" )
	return ip6;

 ip6 = ip6["data"];
 
 if ( ! isnull(ip6_vfc) )  ip6["ip6_vfc"] = ip6_vfc;
 if ( ! isnull(ip6_flow) ) ip6["ip6_flow"]    = ip6_flow;
 if ( ! isnull(ip6_plen) ) ip6["ip6_plen"]    = ip6_plen;
 if ( ! isnull(ip6_nxt) )  ip6["ip6_nxt"]     = ip6_nxt;
 if ( ! isnull(ip6_hlim) )  ip6["ip6_hlim"]     = ip6_hlim;
 if ( ! isnull(ip6_src) )  ip6["ip6_src"]     = ip6_src;
 if ( ! isnull(ip6_dst) )  ip6["ip6_dst"]     = ip6_dst;

 ret["data"] = ip6;
 ret["type"] = "ip6";
 return ret;
} 


#
# Create a fresh new packet, with useful default values
#
function ip6(ip6_vfc, ip6_flow, ip6_plen, ip6_nxt, ip6_hlim, ip6_src, ip6_dst)
{
 local_var empty;
 if ( isnull(ip6_vfc) )  ip6_vfc   = 6 << 4;
 if ( isnull(ip6_flow) ) ip6_flow = 0;
 if ( isnull(ip6_plen) ) ip6_plen = 0;
 if ( isnull(ip6_nxt) ) ip6_nxt = IPPROTO_TCP;
 if ( isnull(ip6_hlim) ) ip6_hlim = 64;
 if ( isnull(ip6_src ) ) ip6_src = this_host_raw();
 if ( isnull(ip6_dst ) ) ip6_dst = get_host_raw_ip();

 empty["type"] = "ip6";
 empty["data"] = NULL;

 return ip6_set(ip6:empty,
		ip6_vfc:ip6_vfc,
		ip6_flow:ip6_flow,
		ip6_plen:ip6_plen,
		ip6_nxt:ip6_nxt,
		ip6_hlim:ip6_hlim,
		ip6_src:ip6_src,
		ip6_dst:ip6_dst);
}



#
# Get any item in our IP packet
#
function ip6_get(ip6, element)
{
 local_var t, l, ret;
 if ( isnull(ip6) || ip6["type"] != "ip6" )
 {
  display("ip6_get: invalid 'ip6' argument\n");
  return NULL;
 }
 ip6 = ip6["data"];
 return ip6[element];
}




#
# Transforms an IPv6 structure into a blob which is suitable to be
# sent over the network
#
function mkip6()
{
 local_var item, ret, n, b, ip6;

 ip6 = _FCT_ANON_ARGS[0];
 
 if ( ip6["type"] != "ip6") 
 {
   display("mkip6 : Bad packet type - ", ip6["type"], "\n");
 } 

 ip6 = ip6["data"];

 foreach item ( ip6_struct )
 {
     if ( ip6_sizes[item] == 24 )
	{
	 n = ord(ret[strlen(ret) - 1]);
	 ret = substr(ret, 0, strlen(ret) - 2);
	 ret += mkdword(n << 24 | ip6[item]);
	}
     if ( ip6_sizes[item] == 8 )   ret += mkbyte(ip6[item]);
     if ( ip6_sizes[item] == 16 )  ret += mkword(ip6[item]);
     if ( ip6_sizes[item] == 128 ) ret += ip6[item]; # 128bits -> can only be ip_src or ip_dst
 }

 return ret;
}

