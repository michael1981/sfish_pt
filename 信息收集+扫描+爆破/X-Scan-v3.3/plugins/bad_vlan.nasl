#TRUSTED 04c6e85976f1fb38ae4c595c514a26ec54b48fc6b59160c3ddea95e732994e255e4c6823a5c08f424d64803368208a0f0d4c1ec39b1fab3f6e78e8a1035f1bfca89e199f28ee7fc16b5769b8f28ceffebb7c4511c60b2ac9a7121c5a1f9add0a7b0a7491a5cbe7a3a8df5f3df080d6c54ca278a49cf47e647c531e2a52f1947eddbf9ceb1bc71a02ed4bf0042c6fcafd9bd2112d1eaf95f03ccb24a7c5921d60247d506fdfa5a90cee53223e06aaea4e1830eea4d5b0038c54f64eac07bf24fd087b6b25bd0cf81742af49d41be39b505702c4b4dff6fd88c8ee650ae097345801ab98129f5d359a0a9f43f1bd37b9a14400d4cbfcd7e4135e3aa4d6e84255d961bfa8d70a9b1badb7e7b4b292ece1e0ffc2080f4c73044559f95e0c508a8032f8e42bd397dd71a2682cfd9ba672c2f22675580dfd5f075ec0bf9daffd6540be84c5c29129cda8b882a2581ae7d43750d7fe7dbbacf2601203a86f03c7993099ec1ca2a9f7c6a0e6cf2661dcd65ce3c570ed0ca52df94c68e9e929be360a1353c9f7df67e993b6e0bcc9ed39fb9d71caf183254f0b7c2aba036748ff309d05c452c450c0869bd91efbdb4744e37f78caa5edec762540e1e2357dd2752ac5c8aaf9b0f74be35d8b0ad513f7331a089978bacb348ca24b26a80b97200464046f94c423183a53e60f72709ea47816f61c30367e8636eb7bd7ed958f4548105dce4e
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(23971);
 script_version("1.6");
 script_name(english:"Host Logical Network Segregation Weakness");
 
 script_set_attribute(attribute:"synopsis", value:
"The physical network is set up in a potentially insecure way." );
 script_set_attribute(attribute:"description", value:
"The remote host is on a different logical network than the
Nessus scanner. However, it is on the same physical subnet.

An attacker connecting from the same network as your Nessus
scanner could reconfigure his system to force it to belong
to the subnet of the remote host.

This may allow an attacker to bypass network filtering between
the two subnets." );
 script_set_attribute(attribute:"solution", value:
"Use VLANs to separate different logical networks." );
 script_set_attribute(attribute:"risk_factor", value:
"Low" );

script_end_attributes();

 
 script_summary(english:"Performs an ARP who-is on the remote host");
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 exit(0);
}


#


# ByteFunc included here
BYTE_ORDER_BIG_ENDIAN  		= 1;
BYTE_ORDER_LITTLE_ENDIAN 	= 2;

ByteOrder = BYTE_ORDER_BIG_ENDIAN;

function set_byte_order()
{
 ByteOrder = _FCT_ANON_ARGS[0];
}

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

 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
 	return  raw_string((l >> 8) & 0xFF, l & 0xFF);
 else
 	return  raw_string(l & 0xff, (l >> 8) & 0xff);
}


function mkdword()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
	 return  raw_string( (l >> 24 ) & 0xff,
		     	     (l >> 16 ) & 0xff,
		     	     (l >>  8 ) & 0xff,
		     	     (l)   & 0xff);
 else
	 return  raw_string( l & 0xff,
		     	    (l >> 8) & 0xff,
		            (l >> 16) & 0xff,
		            (l >> 24)   & 0xff);
}


function getdword(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 4 )
	return NULL;

 s = substr(blob, pos, pos + 3);
 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
  return ord(s[0]) << 24 | ord(s[1]) << 16 | ord(s[2]) << 8 | ord(s[3]);
 else
  return ord(s[0]) | ord(s[1]) << 8 | ord(s[2]) << 16 | ord(s[3]) << 24;
}

function getword(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 2 )
	return NULL;
 s = substr(blob, pos, pos + 1);
 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
  return ord(s[0]) << 8 | ord(s[1]);
 else
  return ord(s[0]) | ord(s[1]) << 8;
}

function getbyte(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 1 )
	return NULL;
 s = substr(blob, pos, pos);
 return ord(s[0]);
}




function mkpad()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return crap(data:raw_string(0), length:l);
}





function mkipaddr()
{
 local_var ip;
 local_var str;

 ip = _FCT_ANON_ARGS[0];
 str = split(ip, sep:'.', keep:FALSE);
 return raw_string(int(str[0]), int(str[1]), int(str[2]), int(str[3])); 
}


function is_class_b(a,b)
{
 local_var aa, ab;
 local_var i;

 aa = split(a, sep:'.', keep:FALSE);
 ab = split(b, sep:'.', keep:FALSE);
 
 for ( i = 0 ; i < 4 ; i ++ )
 {
   if ( aa[i] != ab[i] ) break;
 }

 if ( i < 2 ) return FALSE;
 else return TRUE;
}


function arp_ping()
{
 local_var broadcast, macaddr, arp, ethernet, i, r, srcip, dstmac;

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

 for ( i = 0 ; i < 2 ; i ++ )
 {
  r = inject_packet(packet:arp, filter:"arp and arp[7] = 2 and src host " + get_host_ip(), timeout:1);
  if ( ! r || strlen(r) <= 31 ) continue;
  srcip = substr(r, 28, 31);
  if ( srcip == mkipaddr(get_host_ip() ) )
   {
    dstmac = substr(r, 6, 11);
    dstmac = strcat(hexstr(dstmac[0]), ":",
	            hexstr(dstmac[1]), ":",
		    hexstr(dstmac[2]), ":",
		    hexstr(dstmac[3]), ":",
		    hexstr(dstmac[4]), ":",
		    hexstr(dstmac[5]));
    return dstmac;
   }
  }
}

# Nessus 3 only
if ( ! defined_func("inject_packet") ) exit(0);
if ( ! isnull(get_gw_mac_addr()) ) exit(0);

# If the target is officially in the same subnet, exit
if ( islocalnet() || TARGET_IS_IPV6 ) exit(0);

opt = get_kb_item("global_settings/thorough_tests");
if (! opt || "yes" >!< opt  )
	# If the target is not at least in the same class B, exit
	if ( ! is_class_b(a:this_host(), b:get_host_ip() ) ) exit(0);



if ( mac = arp_ping() )
{
 if ( mac == get_gw_mac_addr() ) exit(0); # Arp proxy
 replace_kb_item(name:"ARP/mac_addr", value:mac);
 security_note(port:0,extra:"The MAC address of the remote host is " + mac );
}
