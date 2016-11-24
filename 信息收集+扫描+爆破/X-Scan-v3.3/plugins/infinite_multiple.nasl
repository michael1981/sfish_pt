#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16278);
 script_cve_id("CVE-2005-0323", "CVE-2005-0324");
 script_bugtraq_id(12399); 
 script_xref(name:"OSVDB", value:"13320");
 script_xref(name:"OSVDB", value:"13321");
 script_version ("$Revision: 1.9 $");

 script_name(english:"Infinite Mobile Delivery Webmail Multiple Vulnerabilities (XSS, PD)");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a webmail application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"There are flaws in the remote Infinite Mobile Delivery, a web 
interface to provide wireless access to mail.

This version of Infinite Mobile Delivery has a cross site scripting
vulnerability and a path disclosure vulnerability. 

An attacker, exploiting this flaw, would be able to steal user 
credentials or use disclosed information to launch further attacks." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0328.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
 script_end_attributes();
 
 summary["english"] = "Checks for the presence of Infinite Mobile Delivery";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var res;

 res = http_send_recv3(method:"GET", item:string(loc, "/"),port:port);
 if (isnull(res)) exit(1, "The remote web server did not respond.");

 if ( egrep(pattern:"^Powered by .*Infinite Mobile Delivery v([0-1]\..*|2\.[0-6]).* -- &copy; Copyright [0-9]+-[0-9]+ by .*Captaris", string:res[2]))
 {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

