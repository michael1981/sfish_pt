#
# (C) Tenable Network Security, Inc.
#
# References:
# From: "karol _" <su@poczta.arena.pl>
# To: bugtraq@securityfocus.com
# CC: arslanm@Bilkent.EDU.TR
# Date: Fri, 06 Jul 2001 21:04:55 +0200
# Subject: basilix bug
#


include("compat.inc");

if(description)
{
 script_id(11072);
 script_bugtraq_id(2995);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2001-1045");
 script_xref(name:"OSVDB", value:"8956");

 name["english"] = "Basilix Webmail basilix.php3 request_id[DUMMY] Variable Traversal Arbitrary File Access";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include attack." );
 script_set_attribute(attribute:"description", value:
"The script 'basilix.php3' is installed on the remote web server.  Some
versions of this webmail software allow the users to read any file on
the system with the permission of the webmail software, and execute any
PHP." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-07/0114.html" );
 script_set_attribute(attribute:"solution", value:
"Update Basilix or remove DUMMY from lang.inc." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for the presence of basilix.php3";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 

 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencies("http_version.nasl", "logins.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("imap/login", "imap/password", "Settings/ParanoidReport");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass)
  exit(1, "imap/login and/or imap/password are empty");


url=string("/basilix.php3?request_id[DUMMY]=../../../../../../../../../etc/passwd&RequestID=DUMMY&username=", user, "&password=", pass);
if(is_cgi_installed3(port:port, item:url)){ security_hole(port); exit(0); }
