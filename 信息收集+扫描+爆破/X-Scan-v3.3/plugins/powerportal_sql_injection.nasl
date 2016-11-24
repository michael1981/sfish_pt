#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(15760);
 script_version("$Revision: 1.7 $");
 script_bugtraq_id(11681);
 script_xref(name:"OSVDB", value:"11876");
 
 script_name(english:"PowerPortal index.php index_page Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to execute arbitrary commands on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is using PowerPortal, a content management system, 
written in PHP. 

A vulnerability exists in the remote version of this product which may 
allow a remote attacker to perform a SQL injection attack against the 
remote host.

An attacker may exploit this flaw to execute arbitrary SQL statements 
against the remote database and possibly to execute arbitrary commands 
on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks the version of the remote PowerPortal Installation");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("powerportal_privmsg_html_injection.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
kb = get_kb_item("www/" + port + "/powerportal");
if ( ! kb ) exit(0);
matches = eregmatch(string:kb, pattern:"^(.+) under (/.*)$");
if ( ereg(pattern:"^(0\..*|1\.[0-3]([^0-9]|$))", string:matches[1]) )
{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
