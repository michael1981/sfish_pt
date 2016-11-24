#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(15780);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2004-1315");
 script_bugtraq_id(11716);
 script_xref(name:"OSVDB", value:"11719");
 
 script_name(english:"phpBB viewtopic.php highlight Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to SQL injection." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpBB.

There is a flaw in the remote software which may allow anyone to inject
arbitrary SQL commands in the login form.

An attacker may exploit this flaw to bypass the authentication of the 
remote host or execute arbitrary SQL statements against the remote 
database." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = matches[1];

if ( ereg(pattern:"^([01]\.|2\.0\.([0-9]|10)([^0-9]|$))", string:version ) )
{
	security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}

