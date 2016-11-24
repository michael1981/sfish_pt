#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(16126);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(12227);

 name["english"] = "HylaFAX Remote Access Control Bypass Vulnerability";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by an access
control bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running HylaFAX, a fax transmission software.

It is reported that HylaFAX is prone to an access control bypass
vulnerability. An attacker, exploiting this flaw, may be able to gain
unauthorized access to the service." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.hylafax.org//show_bug.cgi?id=610" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.2.1 or later as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Determines if HylaFAX is vulnerable to access control bypass.";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);

 script_require_ports(4559);
 exit(0);
}

port = 4559;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

r = recv(socket:soc, length:4096);
if (!r) exit (0);

if (egrep(pattern:"^220.*\(HylaFAX \(tm\) Version ([0-3]\.|4\.([0-1]\.|2\.0))", string:r))
 {
 security_hole(port);
 exit(0);
 }
