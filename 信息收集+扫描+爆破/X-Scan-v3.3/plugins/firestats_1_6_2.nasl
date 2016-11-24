#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39621);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-2143", "CVE-2009-2144");
  script_bugtraq_id(35367, 35533);
  script_xref(name:"milw0rm", value:"8945");
  script_xref(name:"OSVDB", value:"55087");
  script_xref(name:"OSVDB", value:"55088");
  script_xref(name:"Secunia", value:"35400");

  script_name(english:"FireStats < 1.6.2 Multiple Vulnerabilities");
  script_summary(english:"Does a version check for FireStats");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web application on the remote host has multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "According to its version number, the install of FireStats running on\n",
      "the remote host has multiple vulnerabilities, including :\n",
      "\n",
      "  - A remote file include vulnerability in the\n",
      "    'fs_javascript' parameter of 'firestats-wordpress.php'.\n",
      "    (CVE-2009-2143)\n",
      "\n",
      "  - An unspecified SQL injection vulnerability. (CVE-2009-2144)"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://firestats.cc/wiki/ChangeLog#a1.6.2-stable13062009"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to FireStats 1.6.2-stable or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

installs = make_array();

dirs = make_list(cgi_dirs());

# FireStats can also be installed as a WordPress plugin
wp_install = get_kb_item('www/' + port + '/wordpress');
if (wp_install)
{
  match = eregmatch(string:wp_install, pattern:'^.+ under (/.*)$');
  wp_dir = string(match[1], '/wp-content/plugins/firestats');
  if (match) dirs = list_uniq(make_list(dirs, wp_dir));
}

if (thorough_tests) dirs = list_uniq(make_list('/firestats', dirs));

foreach dir (dirs)
{
  url = string(dir, '/');
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server is not responding.");

  # First, try to detect FireStats
  if (
    '<title>FireStats</title>' >< res[2] &&
    "href='http://firestats.cc'><img alt='FireStats'" >< res[2]
  )
  {
    pattern = '<span class="normal_font" style="padding-left:10px">([0-9.]+)';
    match = eregmatch(string:res[2], pattern:pattern, icase:TRUE);

    # Only do the version check if it looks like we have a version (obviously)
    if (match)
    {
      ver = match[1];
      ver_fields = split(ver, sep:'.', keep:FALSE);
      major = ver_fields[0];
      minor = ver_fields[1];
      rev = ver_fields[2];

      # Affects versions < 1.6.2
      if (
        major < 1 ||
       (major == 1 && minor < 6) ||
       (major == 1 && minor == 6 && rev < 2)
      )
      {
        if (installs[ver]) installs[ver] += ';' + url;
        else installs[ver] = url;
      }
    }

    # Scan for multiple installations only if "Thorough Tests" is checked.
    if (installs && !thorough_tests) break;
  }
}


# Report findings.
if (max_index(keys(installs)))
{
  if (report_verbosity)
  {
    info = "";
    n = 0;
    foreach ver (sort(keys(installs)))
    {
      info += '  Version : ' + ver + '\n';
      foreach dir (sort(split(installs[ver], sep:";", keep:FALSE)))
      {
        info += '  URL     : ' + build_url(port:port, qs:dir) + ' \n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following vulnerable instance';
    if (n == 1) report += ' of FireStats was';
    else report += 's of FireStats were';
    report += ' detected on the remote host :\n\n' + info;

    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
