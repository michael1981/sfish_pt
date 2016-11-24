#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added CVE / OSVDB refs (3/25/2009)


include("compat.inc");

if(description)
{
 script_id(18290);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2005-1361", "CVE-2005-1363", "CVE-2005-1622");
 script_bugtraq_id(13385, 13384, 13383, 13382, 13639);
 script_xref(name:"OSVDB", value:"15871");
 script_xref(name:"OSVDB", value:"16706");

 script_name(english:"MetaCart E-Shop productsByCategory.ASP Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the MetaCart e-Shop, an online store
written in ASP. 

Due to a lack of user input validation, the remote version of this
software is vulnerable to various SQL injection and cross-site
scripting attacks. 

An attacker may exploit these flaws to execute arbitrary SQL commands
against the remote database or to perform a cross site scripting
attack using the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0426.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0427.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0428.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0429.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0196.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


 summary["english"] = "MetaCart E-Shop productsByCategory.ASP XSS and SQL injection Vulnerabilities";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2009 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);

function check(url)
{
 local_var req, res;

 req = http_get(item:url +"/productsByCategory.asp?intCatalogID=3'&strCatalog_NAME=Nessus", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 # Check for the SQL injection
 if ("80040e14" >< res && "cat_ID = 3'" >< res )
 {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
     exit(0);
 }
}

foreach dir ( make_list (cgi_dirs()) )
{
  check(url:dir);
}
