#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# Ref:
#
# From: "bugtracklist.fm" <bugtracklist@freemail.hu>
# To: <bugtraq@securityfocus.com>
# Subject: TextPortal Default Password Vulnerability
# Date: Sat, 24 May 2003 00:15:52 +0200



include("compat.inc");

if(description)
{
 script_id(11660);
 script_bugtraq_id(7673);
 script_xref(name:"OSVDB", value:"4930");
 script_version("$Revision: 1.12 $");
 
 script_name(english: "TextPortal Default Passwords");
 
 script_set_attribute(attribute:"synopsis", value:
"Default administrator passwords have not been changed." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the TextPortal content management interface.
This set of scripts come with two default administrator passwords :

	- admin
	- 12345
	
At least one of these two passwords is still set. An attacker
could use them to edit the content of the remote website." );
 script_set_attribute(attribute:"solution", value:
"Edit admin_pass.php and change the passwords of these users." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english: "Logs into the remote TextPortal interface");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(dir, passwd, port)
{
 local_var	r;
 r = http_send_recv3(method: 'POST', item: dir + "/admin.php", port: port, 
		data: "op=admin_enter&passw=" + passwd,
		add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );
 if (isnull(r)) exit(0);
 if ("admin.php?blokk=" >< r[1]+r[2]) return(1);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

passwds = make_list("admin", "12345");

if(get_port_state(port))
{
 foreach dir (cgi_dirs())
 {
 	if(is_cgi_installed3(port:port, item:dir + "/admin.php"))
	{
 		foreach pass (passwds)
		{
 			if(check(dir:dir, passwd:pass, port: port))
 			{
 			security_hole(port);
			exit(0);
 			}
 		}	
	}
 }
}
