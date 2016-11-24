#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_version ("$Revision: 1.9 $");
 script_id(11942);
 script_bugtraq_id(9133, 9134);
 
 script_name(english: "VP-ASP shopsearch SQL injection (SQLi)");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to SQL injections." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the VP-ASP CGI suite.

There is a bug in this suite which may allow an attacker
to force it to execute arbitrary SQL statements on the remote
host. An attacker may use this flaw to gain the control of the remote
website and possibly execute arbitrary commands on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Disable this suite or upgrade to the latest version" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english: "Checks for the presence of VP-ASP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencies("http_version.nasl", "no404.nasl");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

enable_cookiejar();

poison = "Keyword='&Category=All&SubCategory=All&action=+Search+";

foreach dir (cgi_dirs())
{
 r = http_send_recv3(port: port, method: 'POST',
    item: strcat(dir, "/shopsearch.asp?search=Yes"), data:poison,
    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );
 if(isnull(r)) exit(0);
 if ("ShopDisplayproducts.asp" >< r[1]+r[2] )
 {
  r = http_send_recv3(port: port, method: 'GET', item: dir + "/ShopDisplayProducts.asp?Search=Yes");
  if (isnull(r)) exit(0);
  if ( egrep(pattern:".*ODBC.*80040e14.*", string: r[1]+r[2]) )
  {
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
  }
  }
}

