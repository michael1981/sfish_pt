#
# (C) Tenable Network Security, Inc. 
#

if ( NASL_LEVEL < 2205 ) exit(0);


include("compat.inc");

if(description)
{
 script_id(27576);
 script_version ("$Revision: 1.8 $");
 script_name(english: "Firewall Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is behind a firewall" );
 script_set_attribute(attribute:"description", value:
"Based on the responses obtained by the TCP scanner, it was possible to
determine that the remote host seems to be protected by a 
firewall." );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 script_summary(english: "Determines if the remote host is behind a firewall");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english: "Firewalls");

 #
 # This plugin only works if nessus_tcp_scanner has run
 #

 script_require_keys("Host/scanners/nessus_tcp_scanner");
 exit(0);
}
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);
if ( ! get_kb_item("Host/scanners/nessus_tcp_scanner") ) exit(0);

open = int(get_kb_item("TCPScanner/OpenPortsNb"));
closed = int(get_kb_item("TCPScanner/ClosedPortsNb"));
filtered = int(get_kb_item("TCPScanner/FilteredPortsNb"));

total = open + closed + filtered;

if (total == 0) exit(0);
if (filtered == 0 ) exit(0);
if ( get_kb_item("TCPScanner/RSTRateLimit") ) exit(0);

if ( filtered > ( closed * 4 ) )
{
	security_note(0);
	set_kb_item(name:"Host/firewalled", value:TRUE);
}
