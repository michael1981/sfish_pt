# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# GPL
#
# Ref: Pekka Savola <pekkas@netcore.fi>

# Changes by Tenable:
# - Added OSVDB ref, changed family (8/13/09)


include("compat.inc");

if(description)
{
 script_id(14316);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2000-0947");
 script_bugtraq_id(1757);
 script_xref(name:"OSVDB", value:"1590");

 script_name(english:"Cfengine CAUTH Command Remote Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote command execution 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"Cfengine is running on this remote host.

Cfengine contains a component, cfd, which serves as a 
remote-configuration client to cfengine.  This version of cfd contains 
several flaws in the way that it calls syslog().  As a result, trusted
hosts and valid users (if access controls are not in place) can cause
the vulnerable host to log malicious data which, when logged, can 
either crash the server or execute arbitrary code on the stack.  In 
the latter case, the code would be executed as the 'root' user." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2328dff9" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 1.6.0a11 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"check for cfengine flaw based on its version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Gain a shell remotely");
 script_require_ports(5308);

 script_dependencies("cfengine_detect.nasl");
 exit(0);
}

port = 5308;
if ( ! get_kb_item("cfengine/running") ) exit(0);

version = get_kb_item("cfengine/version");

if (version)
{
 	if (egrep(pattern:"^1\.([0-5]\..*|6\.0a([0-9]|10)[^0-9])", string:version))
  		security_hole(port);
}
