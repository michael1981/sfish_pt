#TRUSTED 013d45a6acefa53ce03ceee024ad382d5ed0f05e64b464440f1f2965b33685f1306e253288f1be3cb0593112290bb25f60eb1e3c5d0e8e0781ca26d80bee365d20cb84201ea37df5261e842a4f29668a228d9a234f5b0f759dc597f86480f3c9b223f0ae80b78a3db00048778e7f33f3902d482862d06c3956a58c03943bc32c8adf16a43baf9b7188ecf2269fae62d2de955dffe17d15d9b4ba3b6e58df65ad586277bf0c0ffb5ac446798a366f37c28d9b71f2b2f78a1bdcaae7c570adaf85279418dd6b0ecebb1bf1d565086faa1b65c84e0059219243d89a9ccb0cfe19ade7fcaf7170f2524a80a6c2f8b2475f23fec1e3dfe0ae0b6310c09740d99870b2c3f2cd758735e8b61ca2ad67a11ddfa4de214320d553ef0dae1c88a89ab2ee0118e24222b97ce735c4e4b72a9ac7eafddef05d36b4222307f4b26a19fc2acc5ce6df7af70e4ad5e4a94f192bf84b8f1976762941195edc6acf5a9b3b7d13ea3fc20365e54f0b28f827dae970bd7b8954007aa4e037563b373572feaff8176a6f3322d5b3af33fbc0ebf7ad943c60bb0c68277529f2b27e3423baa6ef0d4fc59446e8d96673fb701f7edbe3f7fccf36627195cfd9e422c824d67d4cae4d4b5fc005bdc38c3d399ce1d187ee7e8ce29e93e2fe705caf73ccad2792d9c1d1125a38a01eed80350b5986b32c55f93945757cb3af4b67bfe82ee52c664e7b483823c0
#
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#



#
# UDP
#


# Define a UDP structure
udp_sizes = make_array(
		"uh_sport", 16,
		"uh_dport", 16,
		"uh_ulen",  16,
		"uh_sum",   16);

udp_struct = make_list(
		"uh_sport",
		"uh_dport",
		"uh_ulen",
		"uh_sum");


function udp_checksum(udp, ip, payload)
{
 local_var src, dst, pseudo, udp_r, ret;
 local_var padding;

 if ( ip["type"] != "ip" || udp["type"] != "udp" )
	{
	display("udp_checksum: Bad IP argument\n");
	return NULL;
	}
 ip  = ip["data"];

 
 udp_r = mkudp(udp);
 
 src = ipaddr(ip["ip_src"]);
 dst = ipaddr(ip["ip_dst"]);
 if ( strlen(payload) & 1 == 1 ) padding = raw_string(0);
 else padding = NULL;

 pseudo = src +
	  dst +
	  mkbyte(0) +
	  mkbyte(IPPROTO_UDP) +
	  mkword(strlen(udp_r) + strlen(payload)) + udp_r + payload + padding;

 ret = inet_sum(pseudo);
 return ret;
}

function udp_get(udp, element)
{
 if ( isnull(udp) || udp["type"] != "udp" )
	{
	display("udp_get: Invalid packet\n");
	return NULL;
	}

 udp = udp["data"];
 return udp[element];
}

function udp_set(udp, uh_sport, uh_dport, uh_ulen, uh_sum)
{
 local_var ret;
 if ( isnull(udp) || udp["type"] != "udp" )
 {
  display("udp_set: Bad packet type\n");
  return NULL;
 }

 udp = udp["data"];
 if ( !isnull(uh_sport) ) udp["uh_sport"] = uh_sport;
 if ( !isnull(uh_dport) ) udp["uh_dport"] = uh_dport;
 if ( !isnull(uh_ulen) ) udp["uh_ulen"] = uh_ulen;
 if ( !isnull(uh_sum) ) udp["uh_sum"] = uh_sum;


 ret["type"] = "udp";
 ret["data"] = udp;
 return ret;
}


function mkudp()
{
 local_var item, ret, n, b, udp;

 udp = _FCT_ANON_ARGS[0];
 
 if ( udp["type"] != "udp") 
 {
   display("mkudp : Bad packet type - ", udp["type"], "\n");
 } 

 udp = udp["data"];

 foreach item ( udp_struct )
 {
     if ( udp_sizes[item] == 16 ) ret += mkword(udp[item]);
     else {
	display("Inconsistent UDP structure\n");
	return NULL;
	}
 }

 return ret;
}


function udp(uh_sport, uh_dport, uh_ulen, uh_sum)
{
 local_var empty;
 if ( isnull(uh_sport) ) uh_sport = 1024;
 if ( isnull(uh_dport) ) uh_dport = 53;
 if ( isnull(uh_ulen ) ) uh_ulen  = 8;
 if ( isnull(uh_sum  ) ) uh_sum   = 0;

 empty["type"] = "udp";
 empty["data"] = NULL;
 return udp_set(udp:empty,
		uh_sport:uh_sport,
		uh_dport:uh_dport,
		uh_ulen: uh_ulen,
		uh_sum : uh_sum);
}
