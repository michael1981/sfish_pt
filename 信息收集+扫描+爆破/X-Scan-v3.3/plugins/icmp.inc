#TRUSTED 0cff5b40bca05178ad7b37b50abab4038bf2e74db15b7a1016fb75c090f689d880970bac4f674d3eec2db276db0eae62df517e7af66d8ea2bb48fa2b34279df5f7a168bc6252d3c66fbec6696fe6d07dddeed254ef48171f4238bdbc23ef9669e23501edcbefdec432b80ef0345cc5b4b11efc66500dd7f7c8623edacc83ee4bd61fce01e21d1c1288ba9377329815bbdab3eb14db3be6955ca9acb8aee3468f7edcba34ba490d296c12cf70bf039d3475ebbd2e52c1d5518a5f3f128d6c1141746f55152b915a31f70c9d20665ed09c68e227a8f64dfff70c9476d06c6aee866affe131c6a786d64be0b4987608422e67de92b3960f4834c983d81216a4517dd89ea69830c127ea60286fb9b73428ecdcc18935d45b6ace01e753e387c7ae8a58132e7ec60553da01677d2c907d2e87d531f3b741cb3b50886280ed4e64001ebcadb608a6a292ae0d3fce2b77abfd6b46360801151af9010523e9d64f5700b91611a341b0664b5c7e29abf5026833f7635d707d4ca13153c8fd986e3bae66cc4687c4fa30f99af376ed252517ba89b3a607d127b0727117ca34f79949d9e4d94aa5bc11748741ca59f81075c8c558b100b21f736c960ead84a9fecb99a4b7333a19f6705a677d8206c08501d1cb7d2af596a30ab644c169db26ef429c135760cea8d5da29a5558417037ed2cce7d8eb6d5f13ced2713032f90a72083ddbba28
#
# (C) Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.2


#-------------------------------------------------------------------------#
# ICMP                                                                    #
#-------------------------------------------------------------------------#

ICMPTYPE_UNREACHABLE = 3;
ICMPCODE_NET_UNREACH  = 0;
ICMPCODE_HOST_UNREACH  = 1;
ICMPCODE_PROTO_UNREACH  = 2;
ICMPCODE_PORT_UNREACH  = 3;
ICMPCODE_FRAG_NEEDED  = 4;
ICMPCODE_SOURCE_ROUTE  = 5;

ICMPTYPE_TIME_EXCEEDED = 3;
ICMPTYPE_TTL_EXCEEDED = 0;
ICMPTYPE_FRAG_REASS = 1;

ICMPTYPE_PING = 8;
ICMPTYPE_PONG = 0;

ICMP6TYPE_PING = 128;
ICMP6TYPE_PONG = 129;

# TBD

icmp_sizes = make_array(
	"ih_type",	8,
	"ih_code", 	8,
	"ih_sum",	16,
	"ih_id",	16,
	"ih_seq",	16,
	"ih_data",	-8,
	"ih_gw_addr",	32,
	"ih_orig_ts",	32,
	"ih_rec_ts",	32,
	"ih_trans_ts",	32,
	"ih_ptr",	8,
	"ih_orig_pkt",	-8 );

icmp_offsets = make_array(
	"ih_type",	0,
	"ih_code",	8,
	"ih_sum",	16,
	"ih_id",	32,
	"ih_seq",	48,
	"ih_data",	64,
	"ih_gw_addr",	32,
	"ih_orig_ts",	64,
	"ih_rec_ts",	96,
	"ih_trans_ts",	128,
	"ih_ptr",	32,
	"ih_orig_pkt",	64 );

function icmp_checksum(icmp, ip, payload)
{
 local_var	icmp0, icmp_r, ret,pseudo;

 if ( (ip["type"] != "ip" && ip["type"] != "ip6") || icmp["type"] != "icmp" )
 {
	display("icmp_checksum: Bad IP argument\n");
	return NULL;
 }

 icmp0 = icmp;
 icmp0["ih_sum"] = 0;
 icmp0["ih_data"] = payload;
 icmp_r = mkicmp(icmp0);
 if (ip["type"] == "ip")
 {
   pseudo = icmp_r;
 }
 else if ( ip["type"] == "ip6" )
 {
   ip = ip["data"];
   pseudo = ip["ip6_src"] + 		
           ip["ip6_dst"] + 		
           '\0\0' + 			
           mkword(strlen(icmp_r)) + 	
           '\0\0\0' + 			
           mkbyte(58) +    
           icmp_r;
 }
 ret = inet_sum(pseudo);
 return ret;
}
 
# To be completed
function icmp_set(icmp, ih_type, ih_code, ih_sum, ih_seq)
{
 local_var head, tail, ret, t;

 if ( isnull(icmp) )
 {
  display("set_icmp: NULL ICMP packet\n");
  return NULL;
 }

 if ( icmp["type"] != "icmp" )
  {
	display("set_icmp: bad packet type\n");
	return icmp;
	}

 icmp = icmp["data"];

 if ( ! isnull(ih_type) ) icmp["ih_type"] = ih_type;
 if ( ! isnull(ih_code) ) icmp["ih_code"] = ih_code;
 if ( ! isnull(ih_sum) ) icmp["ih_sum"] = ih_sum;
 if ( ! isnull(ih_seq) ) icmp["ih_seq"] = ih_seq;
# TBD
 ret["type"] = "icmp";
 ret["data"] = icmp;

 return ret;
}


function icmp(ih_type, ih_code, ih_sum, ih_seq)
{
 local_var empty;
 # if ( isnull(ih_seq) ) ih_seq = rand() % 0x7fffffff;
 # TBD
 empty["type"] = "icmp";
 empty["data"] = NULL;
 
 return icmp_set(icmp:empty,
	 	ih_type: ih_type, 
		ih_code: ih_code,
		ih_sum: ih_sum, 
		ih_seq: ih_seq);
}


function icmp_get(icmp, element)
{
 if ( isnull(icmp) || icmp["type"] != "icmp") 
 {
  display("icmp_get: Bad packet type - ", icmp["type"], "\n");
  return NULL;
 }

 icmp = icmp["data"];
 return icmp[element];
}

function mkicmp()
{
 local_var icmp, ret, item,n,b, l;
 local_var	off, sz, blob;

 icmp = _FCT_ANON_ARGS[0];
 if ( icmp["type"] != "icmp" )
 {
  display("mkicmp(): Bad packet type - ", icmp["type"], "\n");
  return NULL;
 }

 icmp = icmp["data"];
 ret =  '\0\0\0\0\0\0\0\0';
 foreach item (keys(icmp_sizes))
 {
   if (isnull(icmp[item])) continue;

   sz = icmp_sizes[item] / 8;
   off = icmp_offsets[item] / 8;

   if ( icmp_sizes[item] == 8 )		blob = mkbyte(icmp[item]);
   else if ( icmp_sizes[item] == 16 )	blob = mkword(icmp[item]);
   else if ( icmp_sizes[item] == 32 )	blob = mkdword(icmp[item]);

   if (off == 0)
     b = '';
   else
   {
     b =  substr(ret, 0, off -1);
     l = strlen(b);
     if (l < off - 1) b = strcat(b, crap(data: '\0', length: off -l - 1));
   }
   if (  sz > 0) 
     ret = strcat(b, blob, substr(ret, off + sz) );
   else	# Variable size
     ret = strcat( b, icmp[item]);
 }
 return ret;
}

