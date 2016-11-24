#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11766);
 script_version ("$Revision: 1.16 $");
 script_bugtraq_id(7980, 7981);
 script_xref(name:"OSVDB", value:"54724");
 script_xref(name:"OSVDB", value:"54725");
 script_xref(name:"OSVDB", value:"54726");

 script_name(english: "pMachine <= 2.2.1 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote CGI is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of pMachine which is vulnerable
to two flaws :
  - It is vulnerable to multiple path disclosure problem which may allow
    an attacker to gain more knowledge about this host
	  
 - It is vulnerable to a cross-site-scripting attack which may allow
   an attacker to steal the cookies of the legitimates users of
   this service" );
 script_set_attribute(attribute:"solution", value:
"None at this time. Disable this CGI suite." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 script_summary(english: "Checks for the presence of search/index.php");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

test_cgi_xss(port: port, dirs: cgi_dirs(), cgi: "/search/index.php", 
  qs: "weblog=nessus&keywords=<script>foo</script>", 
  pass_str: "<script>foo</script>");
