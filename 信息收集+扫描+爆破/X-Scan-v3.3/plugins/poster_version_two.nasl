#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  From: "Peter Winter-Smith" <peter4020@hotmail.com>
#  To: vulnwatch@vulnwatch.org
#  Date: Wed, 14 May 2003 11:19:04 +0000
#  Subject: [VulnWatch] Vulnerability in ' poster version.two'



include("compat.inc");

if (description)
{
 script_id(11629);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2003-0307");
 script_xref(name:"OSVDB", value:"12316");

 script_name(english:"Poster version.two index.php Account Manipulation Privilege Escalation");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application can be reconfigured." );
 script_set_attribute(attribute:"description", value:
"The remote host is running 'poster version.two' a news posting
system written in PHP.

There is a flaw in this version which allows new users to enter a 
specially crafted name which may allow them to gain administrative
privileges on this installation." );
 script_set_attribute(attribute:"solution", value:
"None at this time - disable this CGI." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Checks if Poster version.two is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("webmirror.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");



port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port))exit(0);

dir = list_uniq(make_list("/poster", cgi_dirs()));
		
foreach d (dir)
{
 r = http_send_recv3(method: "GET", item:d + "/index.php", port:port);
 if (isnull(r)) exit(0);
 res= r[0]+r[1]+'\r\n'+r[2];
 if("<title>poster version.two</title>" >< res &&
    "?go=check" >< res &&
    "poster version.two: login" >< res){
    	security_warning(port);
	exit(0);
	}
}
