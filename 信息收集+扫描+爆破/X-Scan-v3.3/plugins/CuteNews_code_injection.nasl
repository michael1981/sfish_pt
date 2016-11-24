#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: "Over_G" <overg@mail.ru>
# To: vuln@security.nnov.ru, bugtraq@securityfocus.com,
#        staff@packetstormsecurity.org
# Subject: PHP code injection in CuteNews
# Message-Id: <E18ndJT-000JS2-00@f19.mail.ru>


include("compat.inc");

if(description)
{
 script_id(11276);
 script_cve_id("CVE-2003-1240");
 script_bugtraq_id(6935);
 script_xref(name:"OSVDB", value:"5957");
 script_xref(name:"OSVDB", value:"6051");
 script_xref(name:"OSVDB", value:"6052");

 script_version ("$Revision: 1.17 $");

 script_name(english:"CuteNews Multiple Script cutepath Parameter Arbitrary Command Execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is subject to
multiple remote file include attacks." );
 script_set_attribute(attribute:"description", value:
"The version of CuteNews installed on the remote host fails to sanitize
input to the 'cutepath' parameter before using it in various scripts
to include PHP code.  An attacker may use this flaw to inject
arbitrary code in the remote host and gain a shell with the privileges
of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-02/0320.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CuteNews 0.89 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for the presence of search.php";
 
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("cutenews_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
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
if(!can_host_php(port:port)) exit(0);



# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 w = http_send_recv3(method: "GET", item:string(loc, "/search.php?cutepath=http://xxxxxxxx"), port:port);			
 if (isnull(w))exit(0);
 r = w[2];
 if(egrep(pattern:".*http://xxxxxxxx/config\.php", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}
