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
 script_id(14285);
 script_version ("$Revision: 1.6 $");
 script_xref(name:"OSVDB", value:"8641");
 script_name(english:"CVSTrac Database Plaintext Password Storage");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that stores 
passwords in plaintext." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running cvstrac, a web-based bug and 
patch-set tracking system for CVS.

This version contains a flaw related to *.db files that may allow an 
attacker to gain access to plaintext passwords.

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of CVSTrac
***** installed there." );
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/chngview?cn=110" );
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/tktview?tn=28" );
 script_set_attribute(attribute:"solution", value:
"Update to version 1.1.4 or later as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


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

if(ereg(pattern:"^(0\..*|1\.0\.[0-5]([^0-9]|$))", string:version))
	security_warning( port );
