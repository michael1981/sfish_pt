#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) 
{
  script_id(22089);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-7071");
  script_bugtraq_id(18984);
  script_xref(name:"OSVDB", value:"27352");

  script_name(english:"Invision Power Board classes/class_session.php CLIENT_IP HTTP Header SQL Injection");
  script_summary(english:"Checks version of IPB");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the installation of Invision Power Board on
the remote host reportedly fails to sanitize input to the 'CLIENT_IP'
HTTP request header before using it in database queries.  An
unauthenticated attacker may be able to leverage this issue to
disclose sensitive information, modify data, or launch attacks against
the underlying database. 

Note that it's unclear whether successful exploitation depends on any
PHP settings, such as 'magic_quotes'." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2010" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eea8694e" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Invision Power Board 2.1.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(pattern:"^(.+) under (/.*)$", string:install);
if (!isnull(matches))
{
  ver = matches[1];

  if (ver && ver =~ "^([01]\.|2\.(0\.|1\.[0-6][^0-9]?))")
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
