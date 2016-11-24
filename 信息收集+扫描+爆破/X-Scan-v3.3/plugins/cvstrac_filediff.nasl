#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security, Inc.
#
# Ref: Richard Ngo (August 2004)
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title (12/22/2008)



include("compat.inc");

if(description)
{
 script_id(14220);
 script_cve_id("CVE-2004-1456");
 script_bugtraq_id(10878);
 script_xref(name:"OSVDB", value:"8373");
 script_version ("$Revision: 1.14 $");
 script_name(english:"CVSTrac filediff Arbitrary Remote Code Execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a cGI application that is affected
by a remote code execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running cvstrac, a web-based bug and 
patch-set tracking system for CVS.

This version of filediff has a flaw in the input sanitation which, 
when exploited, can lead to a remote attacker executing arbitrary
commands on the system.

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of CVSTrac
***** installed there." );
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/chngview?cn=316" );
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/tktview?tn=339" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0054.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0082.html" );
 script_set_attribute(attribute:"solution", value:
"Update to version 1.1.4 or later as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "Checks for CVSTrac version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2008 David Maciejak");
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
if(ereg(pattern:"^(0\.|1\.(0|1\.[0-3]([^0-9]|$)))", string:version))
	security_hole(port);
