#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# This script is released under the GNU GPL v2
#
# Changes by Tenable:
# - Revised plugin title (12/22/2008)



include("compat.inc");

if(description)
{
 script_id(14284);
 script_version ("$Revision: 1.7 $");
 #script_cve_id("CVE-MAP-NOMATCH");
 script_xref(name:"OSVDB", value:"8637");
 script_xref(name:"OSVDB", value:"8640");
 script_name(english:"CVSTrac cgi.c Multiple Overflows");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by multiple remote overflows." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running cvstrac, a web-based bug and
patch-set tracking system for CVS.

This version contains multiple flaws in the mprintf, vmprintf, and 
vxprintf functions in cgi.c .  A remote attacker, exploiting this 
flaw, would be able to execute arbitrary code on the remote system.

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of CVSTrac
***** installed there." );
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/chngview?cn=77" );
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/chngview?cn=92" );
 script_set_attribute(attribute:"solution", value:
"Update to version 1.1.4 or later as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "Checks for CVSTrac version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("cvstrac_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);
kb = get_kb_item("www/" + port + "/cvstrac" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
version = stuff[1];

if(ereg(pattern:"^(0\..*|1\.(0\.|1\.[0-3]([^0-9]|$)))", string:version)) security_hole(port);
