# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised title and description (12/22/2008)



include("compat.inc");

if(description)
{
 script_id(24263);
 script_version ("$Revision: 1.5 $");

 script_cve_id("CVE-2007-0347");
 script_bugtraq_id(22296);
 script_xref(name:"OSVDB", value:"31935");

 script_name(english:"CVSTrac Text Output Formatter SQL Injection DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script or is itself subject to a
denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the version of CVSTrac installed on 
the remote host contains a flaw related to its Wiki-style text output 
formatter that may allow an attacker to cause a partial denial of service,
depending on the pages requested, via limited SQL injection." );
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/tktview?tn=683" );
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/chngview?cn=850" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/458455/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CVSTrac 2.0.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P" );


script_end_attributes();

 
 summary["english"] = "Checks CVSTrac version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("cvstrac_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
kb = get_kb_item("www/" + port + "/cvstrac" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
version = stuff[1]; 
if(ereg(pattern:"^([01]\.|2\.0\.0[^0-9.]?)", string:version))
	security_warning(port);
