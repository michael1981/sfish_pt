#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title, update solution (4/2/2009)


include("compat.inc");

if(description)
{
 script_id(13655);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(10722);
 script_xref(name:"OSVDB", value:"7811");
 script_xref(name:"OSVDB", value:"7814");

 script_name(english:"phpBB < 2.0.9 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to SQL injection." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpBB older than 2.0.9.

There is a flaw in the remote software which may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host or to obtain
the MD5 hash of the password of any user.

One vulnerability is reported to exist in 'admin_board.php'. 
The other pertains to improper characters in the session id variable." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 2.0.9" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"SQL Injection");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 
 script_family(english:"CGI abuses");
 script_dependencie("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = matches[1];
if ( ereg(pattern:"^([01]\.|2\.0\.[0-8]([^0-9]|$))", string:version) )
{
	security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
