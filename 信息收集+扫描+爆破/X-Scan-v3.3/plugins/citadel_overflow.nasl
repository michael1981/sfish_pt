#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(13856);
 script_cve_id("CVE-2004-1705");
 script_bugtraq_id(10833);
 script_xref(name:"OSVDB", value:"8280");
 script_xref(name:"Secunia", value:"12197");

 script_version("$Revision: 1.10 $");

 script_name(english:"Citadel/UX USER Command Remote Overflow");
 script_summary(english:"Checks the version of the remote Citadel server");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote messaging service has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running Citadel/UX, a messaging server for Unix.\n\n",
     "There is a buffer overflow in the remote version of this software\n",
     "which may be exploited by a remote attacker to create a denial of\n",
     "service, or execute arbitrary code.\n\n",
     "To exploit this flaw, an attacker would need to provide a specially\n",
     "crafted argument to the USER command."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-07/0337.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Citadel 6.24 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/citadel/ux", 504);
 exit(0);
}


port = get_kb_item("Services/citadel/ux");
if ( ! port ) port = 504;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

greetings = recv_line(socket:soc, length:4096);
if ( ! ( greetings =~ "^200.*Citadel(/UX)?.*" ) ) exit(0);

send(socket:soc, data:'INFO\r\n');
for ( i = 0 ; i < 15 ; i ++ )
{
 r = recv_line(socket:soc, length:4096);
 if ( ! r ) break;
 if ( r =~ "^000" ) break;
 data += r;
}

version = egrep(pattern:"^Citadel(/UX)? [0-9.]*", string:data);
if ( version )
{
 version = chomp(version);
 set_kb_item(name:"citadel/" + port + "/version", value:version);
 version = egrep(pattern:"^Citadel(/UX)? ([0-5]\..*|6\.([0-1][0-9]|2[0-3])[^0-9])",
		string:data);

if ( version )
	security_hole(port);
}

