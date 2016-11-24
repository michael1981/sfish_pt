#
# This script was written by Frank Berger <dev.null@fm-berger.de>
# <http://www.fm-berger.de>
#
# License: GPL v 2.0  http://www.gnu.org/copyleft/gpl.html
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, enhanced description, replaced 404 URL (6/10/09)


include("compat.inc");

if(description)
{
 script_id(11918);
 script_version("$Revision: 1.8 $");
 script_xref(name:"OSVDB", value:"2763");

 script_name(english:"Oracle 9iAS Multiple Portal Component SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"In your installation of Oracle 9iAS, it is possible to access 
a demo (PORTAL_DEMO.ORG_CHART) via mod_plsql. Access to these pages should
be restricted, because it may be possible to abuse this demo for 
SQL Injection attacks.

Additional components of the Portal have been reported as vulnerable
to SQL injection attacks. However, Nessus has not tested for these." );
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technology/deploy/security/pdf/2003alert61_2.pdf" );
 script_set_attribute(attribute:"solution", value:
"Remove the Execute for Public grant from the PL/SQL package in schema
PORTAL_DEMO (REVOKE execute ON portal_demo.org_chart FROM public;).
Please check also Oracle Security Alert 61 for patch-information." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Tests for presence of Oracle9iAS PORTAL_DEMO.ORG_CHART");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Frank Berger");
 script_family(english:"Databases");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80, 7777, 7778, 7779);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

# Make a request for the Admin_ interface.
 req = http_get(item:"/pls/portal/PORTAL_DEMO.ORG_CHART.SHOW", port:port);	      
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if( "Organization Chart" >< res )
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
