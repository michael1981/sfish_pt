#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(20316);
 script_cve_id("CVE-2005-4310");
 script_bugtraq_id(15903);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "SSH Tectia Server Host Authentication Authorization Bypass Vulnerability";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to bypass the authentication of the remote ssh server." );
 script_set_attribute(attribute:"description", value:
"You are running a version of Tectia SSH server which is older than 5.0.1.

Versions older than 5.0.1 are vulnerable to a flaw in which an attacker
may bypass the authentication routine. 
However the ssh server must be configured to use Host-Based authentication
only." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Tectia SSH server 5.0.1 and later" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks for the remote SSH version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = tolower(banner);

if("ssh tectia server" >< banner)
{
 if(ereg(pattern:"^ssh-2.0-([0-4]\..*|5.0.0.*) ssh tectia server.*", string:banner))
	security_hole(port);
}
