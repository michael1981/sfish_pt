#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(22315);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-4674");
  script_bugtraq_id(19911);
  script_xref(name:"OSVDB", value:"30956");

  script_name(english:"DokuWiki doku.php X-FORWARDED-FOR HTTP Header Arbitrary Code Injection");
  script_summary(english:"Checks whether DocuWiki dwpage.php is accessible via http");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that should be removed or
protected." );
 script_set_attribute(attribute:"description", value:
"The remote host is running DokuWiki, an open-source wiki application
written in PHP. 

The installed version of DokuWiki includes a script, 'bin/dwpage.php',
that is intended as a commandline tool for modifying pages.  By
accessing it through the web, an unauthenticated remote attacker can
abuse it to view local files and even execute arbitrary code, both
subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/dokuwiki_2006-03-09b_cmd.html" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2322" );
 script_set_attribute(attribute:"see_also", value:"http://www.freelists.org/archives/dokuwiki/09-2006/msg00064.html" );
 script_set_attribute(attribute:"solution", value:
"Limit access to DokuWiki's 'bin' directory using, say, a .htaccess
file or remove the affected script." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("dokuwiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/dokuwiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Call the script's help function
  r = http_send_recv3(method: "GET", item:string(dir, "/bin/dwpage.php?-h"), port:port);
  if (isnull(r)) exit(0);

  # If it does...
  if ("Usage: dwpage.php [opts] <action>" >< r[2])
  {
    security_hole(port);
    exit(0);
  }
}
