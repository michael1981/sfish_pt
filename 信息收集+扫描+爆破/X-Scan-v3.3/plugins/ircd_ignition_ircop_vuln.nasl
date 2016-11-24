#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# Ref: vendor
#
# This script is released under the GNU GPL v2


include("compat.inc");

if(description)
{
 script_id(14388);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2004-2553");
 script_bugtraq_id(9783);
 script_xref(name:"OSVDB", value:"4121");
 
 script_name(english:"ignitionServer umode Command Global Operator Privilege Escalation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote instant messaging server is affected by a privilege
escalation issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the IgnitionServer IRC service
which may be vulnerable to a flaw that lets a remote attacker gain
elevated privileges on the system.  A local IRC operator can supply an
unofficial command to the server to obtain elevated privileges and
become a global IRC operator." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7503de28" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IgnitionServer 0.2.1-BRC1 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"checks the version of the remote ircd");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl", "find_service2.nasl", "ircd.nasl");
 script_require_ports("Services/irc", 6667);
 exit(0);
}

#the code

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(! get_port_state(port)) exit(0);

key = string("irc/banner/", port);
banner = get_kb_item(key);
if(!banner)exit(0);

if(egrep(pattern:".*ignitionServer 0\.([01]\.|2\.0).*", string:banner)) 
{
 security_warning(port);
 exit(0);
}

