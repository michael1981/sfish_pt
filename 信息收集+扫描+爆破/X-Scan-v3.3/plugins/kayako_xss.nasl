#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16474);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2005-0487");
 script_bugtraq_id(12563);
 script_xref(name:"OSVDB", value:"13921");

 script_name(english:"Kayako eSupport index.php nav Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from a cross-
site scripting flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Kayako eSupport, a web-based support and
help desk application. 

This version of eSupport is vulnerable to a cross-site scripting flaw
involving the 'nav' parameter of the 'index.php' script.  An attacker,
exploiting this flaw, would need to be able to coerce an unsuspecting
user into visiting a malicious website.  Upon successful exploitation,
the attacker would be able to steal credentials or execute browser-
side code." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=full-disclosure&m=110845724029888&w=2" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determines the presence of Kayako eSupport");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


test_cgi_xss(port: port, cgi: "/index.php", 
 qs: "_a=knowledgebase&_j=questiondetails&_i=2&nav=<script>alert(document.cookie)</script>",
 pass_str: "<script>alert(document.cookie)</script>" );
