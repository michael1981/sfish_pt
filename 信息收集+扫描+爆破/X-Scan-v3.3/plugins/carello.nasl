#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11776);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2001-0614");
 script_bugtraq_id(2729);
 script_xref(name:"OSVDB", value:"6591");

 script_name(english:"Carello E-Commerce Carello.dll Command Execution");
 script_summary(english:"Checks for the presence of carello.dll");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web application has a command execution vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be running Carello.dll, a web-based\n",
     "shopping cart.\n\n",
     "Versions up to 1.3 of this web shopping cart have a command execution\n",
     "vulnerability.  This could allow a remote attacker to run arbitrary\n",
     "commands on the system with the privileges of the web server.\n\n",
     "*** Note that no attack was performed, and the version number was\n",
     "*** not checked, so this might be a false alert"
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.westpoint.ltd.uk/advisories/wp-02-0012.txt"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of the software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# Please note that it is possible to test this vulnerability, but
# I suspect that Carello is not widely used, and I am lazy :-)
# 
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed3(item:"Carello.dll", port:port);
if (res) security_hole(port);
