#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_version ("$Revision: 1.14 $");
 script_id(11531);
 script_bugtraq_id(7309, 7310, 7313);
 script_xref(name:"OSVDB", value:"4175");
 
 script_name(english:"phPay admin/phpinfo.php Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phPay, an online shop management system.

This package contains multiple information leakages which may allow an 
attacker to obtain the physical path of the installation on the remote
host or even the exact version of the components used by the remote host,
by using the file admin/phpinfo.php which comes with it.

This files make a call to phpinfo() which display a lot of information
about the remote host and how PHP is configured.

An attacker may use this flaw to gain a more intimate knowledge about 
the remote host and better prepare its attacks.

In addition to this, this version is vulnerable to a cross-site-scripting
issue which may let an attacker steal the cookies of your legitimate users." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phPay 2.2.1 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );


script_end_attributes();

 script_summary(english: "Checks for the presence of phpinfo.php");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencies("http_version.nasl");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

foreach dir (list_uniq("/phpay", cgi_dirs()))
{
 r = http_send_recv3(method: "GET", item:string(dir, "/admin/phpinfo.php"), port:port);
 if (isnull(r)) exit(0);
 if("<title>phpinfo()</title>" >< r[2])
 	{
	security_warning(port);
#	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
	}
}
