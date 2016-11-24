#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11369);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2000-0283", "CVE-2000-1193");
 script_bugtraq_id(1106, 4642);
 script_xref(name:"OSVDB", value:"1283");
 script_xref(name:"OSVDB", value:"2069");
 
 script_name(english:"Irix Performance Copilot Service Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The service 'IRIX performance copilot' is running.

This service discloses sensitive information about the remote host,
and may be used by an attacker to perform a local denial of service.

*** This warning may be a false positive since the presence
*** of the bug was not verified locally." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-04/0056.html" );
 script_set_attribute(attribute:"solution", value:
"Restrict access through the pmcd.conf file." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks the presence of IRIX copilot");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc."); 

 script_require_ports(4321);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

port = 4321;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 r = recv(socket:soc, length:20);
 m = raw_string(0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00);
 if(m >< r) {
 	register_service(port:port, proto:"copilot");
 	security_warning(port);
	}
}
