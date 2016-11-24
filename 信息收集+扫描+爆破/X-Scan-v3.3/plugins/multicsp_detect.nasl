#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10418);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2000-0109");
 script_bugtraq_id(1080);
 script_xref(name:"OSVDB", value:"320");

 script_name(english:"Standard & Poor's ComStock MultiCSP Default Account");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be running a client application for a stock
quote server." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be a Standard & Poor's MultiCSP system.

These systems are known to be very insecure, and an intruder may
easily break into it to use it as a launch pad for other attacks.

In addition, these units ship with several default accounts with a
blank or easily guessed password. However, Nessus has not checked 
for it." );
 script_set_attribute(attribute:"solution", value:
"Protect this host by a firewall" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Detect if the remote host is a Standard & Poors' MultiCSP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_require_ports("Services/telnet", 23);
 script_dependencies("find_service1.nasl");
 exit(0);
}

#
# The script code starts here
#
include("telnet_func.inc");

port = get_kb_item("Services/telnet");
if(!port)port = 23;
if (get_port_state(port))
{
 banner = get_telnet_banner(port: port);
 if(banner)
   {
   if("MCSP - Standard & Poor's ComStock" >< banner)
      security_hole(port:port, data:banner);
   }
}
