#
# (C) Tenable Network Security, Inc.
#

# Date: Thu, 9 Jan 2003 00:50:48 +0200 (EET)
# From: Jouko Pynnonen <jouko@solutions.fi>
# To: <vulnwatch@vulnwatch.org>
# Subject: [VulnWatch] IMP 2.x SQL injection vulnerabilities


include("compat.inc");

if(description)
{
 script_id(11488);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2003-0025");
 script_bugtraq_id(6559); 
 script_xref(name:"OSVDB", value:"10105");
 
 script_name(english:"Horde IMP mailbox.php3 Multiple Variable SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple sql injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote server is running IMP, a web-based mail client.  There is a
bug in the installed version which allows an attacker to perform a SQL
injection attack using the 'actionID' parameter of the 'mailbox.php3'
script.

An attacker may use this flaw to gain unauthorized access to a user
mailbox or to take the control of the remote database." );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=104204786206563&w=2" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks IMP version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

if ( ! can_host_php(port:port) ) exit(0);


dirs = make_list(cgi_dirs(), "/imp", "/horde/imp");

foreach d (dirs)
{
 res = http_send_recv3(method:"GET", item:string(d, "/mailbox.php3?actionID=6&server=x&imapuser=x';somesql&pass=x"), port:port);
 if (isnull(res)) exit(1, "The remote web server did not respond.");

 if('parse error at or near "somesql"' >< res[2]){
   security_hole(port:port);
   set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
   exit(0);
 }
}
