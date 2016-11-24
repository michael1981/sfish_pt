#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10124);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-1999-1046", "CVE-2000-0056");
 script_bugtraq_id(502, 504, 506, 914);
 script_xref(name:"OSVDB", value:"9005");

 script_name(english:"Imail IMonitor Service Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Imail IMAP server. The installed
version is reportedly affected by a buffer overflow vulnerability in 
the IMonitor.  An attacker could exploit this flaw in order to cause
a denial of service or potentially execute arbitrary code subject to 
the priviliges of the affected service." );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=92038879607336&w=2" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 
script_end_attributes();

 script_summary(english:"Imail's IMonitor buffer overflow"); 
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_require_ports("Services/imonitor", 8181);	
 script_dependencies("find_service1.nasl");       
 
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/imonitor");
if (! port) port = 8181;
if(! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if (isnull(banner)) exit(0);

if(egrep(pattern:"^Server: IMail_Monitor/([0-5]\.|6\.[01][^0-9])", string:banner))
	security_hole(port);
