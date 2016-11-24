#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(22316);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-4673");
  script_bugtraq_id(19908, 19910);
  script_xref(name:"OSVDB", value:"28613");

  script_name(english:"PHP-Fusion extract() Global Variable Overwriting");
  script_summary(english:"Tries to overwrite $_SERVER[REMOTE_ADDR] with PHP-Fusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
variable overwriting flaw." );
 script_set_attribute(attribute:"description", value:
"The version of PHP-Fusion on the remote host supports registering
variables from user-supplied input in the event that PHP's
'register_globals' setting is disabled, which is the default in
current versions of PHP.  Unfortunately, the way in which this has
been implemented in the version on the remote host does not restrict
the variables that can be registered.  Thus, an unauthenticated remote
attacker can leverage this flaw to launch various attacks against the
affected application." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/phpfusion_6-01-4_xpl.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/445480/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("php_fusion_detect.nasl");
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
install = get_kb_item(string("www/", port, "/php-fusion"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to generate a SQL error.
  host = string(
    rand() % 255, ".", rand() % 255, ".", rand() % 255, ".111",
    "'/**/UNION+SELECT+", SCRIPT_NAME, "--"
  );
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/news.php?",
      "_SERVER[REMOTE_ADDR]=", host));
  if (isnull(r)) exit(0);

  # There's a problem if we see an error w/ the first 3 octets of our "host".
  if (string("syntax to use near '", host - strstr(host, ".111"), "''") >< r[2])
  {
    security_note(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
