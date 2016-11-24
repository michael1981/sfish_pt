#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security, Inc.
#
# Ref: JeiAr <security@gulftech.org>
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (4/7/2009)


include("compat.inc");

if(description)
{
 script_id(14364);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2004-1923", "CVE-2004-1924", "CVE-2004-1925", "CVE-2004-1926", "CVE-2004-1927", "CVE-2004-1928");
 script_bugtraq_id(10100);
 script_xref(name:"OSVDB", value:"5181");
 script_xref(name:"OSVDB", value:"5182");
 script_xref(name:"OSVDB", value:"5183");
 script_xref(name:"OSVDB", value:"5184");
 script_xref(name:"OSVDB", value:"5185");
 script_xref(name:"OSVDB", value:"5186");
 script_xref(name:"OSVDB", value:"5187");
 script_xref(name:"OSVDB", value:"5188");
 script_xref(name:"OSVDB", value:"5189");
 script_xref(name:"OSVDB", value:"5190");
 script_xref(name:"OSVDB", value:"5191");
 script_xref(name:"OSVDB", value:"5192");
 script_xref(name:"OSVDB", value:"5193");
 
 script_name(english:"TikiWiki < 1.8.2 Multiple Input Validation Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running TikiWiki, a content management system
written in PHP. 

The remote version of this software has multiple vulnerabilities that
have been identified in various modules of the application.  These
vulnerabilities may allow a remote attacker to carry out various
attacks such as path disclosure, cross-site scripting, HTML injection,
SQL injection, directory traversal, and arbitrary file upload." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00037-04112004" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-04/0137.html" );
 script_set_attribute(attribute:"see_also", value:"http://tikiwiki.org/tiki-read_article.php?articleId=66" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to TikiWiki 1.8.2 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks the version of TikiWiki");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
function check(loc)
{
 local_var r, req;
 req = http_get(item: loc + "/tiki-index.php", port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if( egrep(pattern:"This is Tiki v(0\.|1\.[0-7]\.|1\.8\.[0-1][^0-9])", string:r) )
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

