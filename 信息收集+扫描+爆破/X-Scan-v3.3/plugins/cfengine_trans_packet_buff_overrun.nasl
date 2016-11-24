# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# GPL
#
# Ref: Nick Cleaton <nick@cleaton.net>


include("compat.inc");

if(description)
{
 script_id(14317);
 script_cve_id("CVE-2003-0849");
 script_bugtraq_id(8699);
 script_xref(name:"OSVDB", value:"2611");

 script_version ("$Revision: 1.7 $");

 script_name(english:"Cfengine cfservd ReceiveTransaction Function Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"Cfengine is running on this remote host.

This version is prone to a stack-based buffer overrun vulnerability. 
An attacker, exploiting this flaw, would need network access to the
server as well as the ability to send a crafted transaction packet
to the cfservd process.  A successful exploitation of this flaw
would lead to arbitrary code being executed on the remote machine
or a loss of service (DoS)." );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=106451047819552&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=106485375218280&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=106546086216984&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to at least 1.5.3-4, 2.0.8 or most recent 2.1 version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "check for cfengine flaw based on its version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");

 family["english"] = "Gain a shell remotely";
 
 script_family(english:family["english"]);
 script_require_ports(5308);

 script_dependencies("cfengine_detect.nasl");
 exit(0);
}

port = 5308;
if ( ! get_kb_item("cfengine/running") ) exit(0);

version=get_kb_item("cfengine/version");
if (version)
{
 	if (egrep(pattern:"(1\.[0-4]\.|1\.5\.[0-2]|1\.5\.3-[0-3]|2\.(0\.[0-7]|1\.0a[0-9][^0-9]))", string:version))
  		security_hole(port);
}

