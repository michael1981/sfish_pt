#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: Frank van Vliet karin@root66.nl.eu.org
#
#  This script is released under the GNU GPL v2
#


include("compat.inc");

if(description)
{
 script_id(15565);
 script_version ("$Revision: 1.8 $");

 script_cve_id("CVE-2000-0421", "CVE-2001-0329");
 script_bugtraq_id(1199);
 script_xref(name:"OSVDB", value:"6362");
 script_xref(name:"OSVDB", value:"6363");
 script_xref(name:"OSVDB", value:"6364");
 script_xref(name:"OSVDB", value:"6365");
 script_xref(name:"OSVDB", value:"6392");
 script_xref(name:"OSVDB", value:"6393");
 script_xref(name:"OSVDB", value:"58527");

 script_name(english:"Bugzilla Multiple Remote Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote Bugzilla bug tracking system, according to its version 
number, is vulnerable to arbitrary commands execution flaws due to a 
lack of sanitization of user-supplied data in process_bug.cgi" );
 script_set_attribute(attribute:"solution", value:
"Upgrade at version 2.12 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 
 summary["english"] = "Checks for the version of bugzilla";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "bugzilla_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

version = get_kb_item(string("www/", port, "/bugzilla/version"));
if(!version)exit(0);


if(ereg(pattern:"(2\.([0-9]|1[01]))[^0-9]*$", string:version))security_hole(port);
