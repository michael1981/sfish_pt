#
# (C) Tenable Network Security, Inc.
#

# Ref :
#  From: "c0wboy@0x333" <c0wboy@tiscali.it>
#  To: <bugtraq@securityfocus.com>
#  Subject: ebola 0.1.4 remote exploit
#  Date: Tue, 9 Dec 2003 18:08:50 +0100
#


include("compat.inc");


if (description)
{
 script_id(11946);
 script_version ("$Revision: 1.4 $");
 script_bugtraq_id(9156);
 script_xref(name:"OSVDB", value:"2905");
 
 script_name(english:"Ebola AV Daemon < 0.1.5 Authentication Sequence Remote Overflow");
 script_summary(english:"Determines if Ebola 0.1.4 or older is running");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote antivirus daemon has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its version number, there is a remote buffer overflow\n",
     "vulnerability in the authentication mechanism of the Ebola AntiVirus\n",
     "daemon.  A remote attacker could exploit this to crash the service, or\n",
     "possibly execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-12/0077.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-12/0121.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.pldaniels.com/ebola/"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Ebola 0.1.5 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencies("find_service2.nasl");
 script_require_ports("Services/ebola", 1665);

 exit(0);
}



port = get_kb_item("Services/ebola");
if(!port)port = 1665;
if(!get_port_state(port))exit(0);


welcome = get_kb_item("ebola/banner/" + port );

if ( ! welcome )
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 welcome = recv_line(socket:soc, length:4096);
 if(!welcome)exit(0);
}


if ( egrep(pattern:"^Welcome to Ebola v0\.(0\.|1\.[0-4][^0-9])", string:welcome) ) security_hole(port);
