#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(22297);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-4466", "CVE-2006-4468", "CVE-2006-4469", "CVE-2006-4470", "CVE-2006-4471",
		"CVE-2006-4472", "CVE-2006-4473", "CVE-2006-4474", "CVE-2006-4475", "CVE-2006-4476");
  script_bugtraq_id(19749);

  script_name(english:"Joomla! < 1.0.11 Multiple Vulnerabilities");
  script_summary(english:"Checks if input to Joomla's administrator page is sanitized");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Joomla installed on the remote host fails to validate
input to the 'administrator/index.php' script, which may let an
attacker launch various attacks against this script. 

In addition, the application reportedly is affected by a number of
other flaws, including arbitrary code execution, cross-site scripting,
and other input validation issues." );
 script_set_attribute(attribute:"see_also", value:"http://www.joomla.org/content/view/1843/74/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla version 1.0.11 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

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

  # Make sure input is sanitized to the index2.php script.
  #
  # nb: if globals.php is included, it will complain because GLOBALS is protected.
  req = http_get(
    item:string(dir, "/administrator/index2.php?GLOBALS=", SCRIPT_NAME), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("Illegal variable" >< res)
  {
    # See whether index.php calls globals.php.
    req = http_get(
      item:string(dir, "/administrator/index.php?GLOBALS=", SCRIPT_NAME), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    if ("Illegal variable" >!< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}
