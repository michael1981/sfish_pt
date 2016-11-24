#
# (C) Tenable Network Security, Inc.
#

# Ref: http://www.isc.org/products/INN/


include("compat.inc");

if(description)
{
 script_id(11984);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-0045");
 script_bugtraq_id(9382);
 script_xref(name:"OSVDB", value:"6872");

 script_name(english:"INN < 2.4.1 Control Message Handling Code Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running INN 2.4.0.

There is a known security flaw in this version of INN which may allow an 
attacker to execute arbitrary code on this server." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-01/0063.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.4.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks INN version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/nntp", 119);
 exit(0);
}




port = get_kb_item("Services/nntp");
if(!port) port = 119;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
  if(soc)
  {
    r = recv_line(socket:soc, length:1024);
    if ( r == NULL ) exit(0);
    if(ereg(string:r, pattern:"^20[0-9] .* INN 2\.4\.0 .*$"))
    {
      security_hole(port);
    }
  }
}
