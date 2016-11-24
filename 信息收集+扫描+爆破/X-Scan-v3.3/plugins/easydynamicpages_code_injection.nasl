#
# (C) Tenable Network Security
#
# Ref:
#  To: BugTraq
#  Subject: include() vuln in EasyDynamicPages v.2.0
#  Date: Jan 2 2004 3:18PM
#  Author: Vietnamese Security Group <security security com vn>
#  Message-ID: <20040102151821.9686.qmail@sf-www3-symnsj.securityfocus.com>


include("compat.inc");

if(description)
{
 script_id(11976);
 script_version ("$Revision: 1.12 $");

 script_cve_id("CVE-2004-0073");
 script_bugtraq_id(9338);
 script_xref(name:"OSVDB", value:"3318");
 script_xref(name:"OSVDB", value:"3408");

 script_name(english:"EasyDynamicPages Multiple Script edp_relative_path Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running EasyDynamicPages, a set of PHP scripts
designed to help web publication. 

It is possible with this suite to make the remote host include PHP
files hosted on a third party server.  An attacker may use this flaw
to inject arbitrary code in the remote host and gain a shell with the
privileges of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-01/0005.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for the presence of EasyDynamicPages";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);



foreach dir (cgi_dirs())
 {
  w = http_send_recv3(method:"GET", item:string(dir, "/dynamicpages/fast/config_page.php?do=add_page&du=site&edp_relative_path=http://xxxxxxxxxx/"),
 		port:port);
 if (isnull(w)) exit(0);
 r = w[2];

 if("http://xxxxxxxxxx/admin/site_settings.php" >< r)
  {
 	security_hole(port);
	exit(0);
  }
}
