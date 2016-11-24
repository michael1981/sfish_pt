#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39006);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(35097);
  script_xref(name:"OSVDB", value:"58154");
  script_xref(name:"milw0rm", value:"8786");

  script_name(english:"lighttpd PHP File Trailing Slash Request Source Disclosure");
  script_summary(english:"Sees if appending a / will yield PHP source code");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The web server running on the remote host has an information\n",
      "disclosure vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(

"

The version of lighttpd installed on the remote host may disclose the
source code of files such as PHP scripts when a '/' is appended to a
URL corresponding to a symbolic link.  This vulnerability occurs only
on certain operating systems (FreeBSD, Mac OS X, and Solaris prior to
version 10 are known to be affected) and arises because of a bug in
the operating system itself in which adding a trailing slash to a
symbolic link pointing to a regular file returns the link itself. 


"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://redmine.lighttpd.net/issues/1989"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to lighttpd 1.4.23 when it becomes available."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("Host/OS");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

function try_exploit(php_file)
{
  local_var res1, res2, report;

  res1 = http_send_recv3(method:"GET", item:php_file, port:port);
  if (isnull(res1)) exit(0);
  
  if (res1[0] =~ '^HTTP/1\\.[01] +200 ')
  {
    res2 = http_send_recv3(method:"GET", item:php_file + "/", port:port);
    if (isnull(res2)) exit(0);
  
    # If the contents differ, and the 2nd response looks like PHP, it's a hit
    if (res2[0] =~ '^HTTP/1\\.[01] +200 ' && res1[2] != res2[2] &&
        '<?' >< res2[2] && '?>' >< res2[2])
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Nessus was able to detect the vulnerability using the following\n",
          "URL :\n\n",
          "  ", build_url(port:port, qs:php_file + "/"), "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
  }
}

#
# Execution starts here
#
# It's going to be difficult to avoid false negatives with this script
# since we have no idea which files on the web server are symlinks.  In an
# attempt to mitigate that, this plugin will try a few different approaches.

os = get_kb_item("Host/OS");
if (isnull(os)) exit(0);

# Bail out if the host is running an OS not affected by this bug
if (
  "Linux" >< os || "NetBSD" >< os || "OpenBSD" >< os ||
  "DragonflyBSD" >< os || "Solaris 10" >< os
) exit (0);

# First, see if /index.php exists. If so, see if requesting it with the
# trailing slash produces different output.
try_exploit(php_file:"/index.php");

# If thorough tests are enabled, try running the check on every PHP file
# picked up by webmirror
if (thorough_tests)
{
  files = get_kb_list("www/" + port + "/content/extensions/php");
  foreach file (files)
    try_exploit(php_file:file);
}

# As a last resort, try doing a version check if we're paranoid
if (report_paranoia < 2) exit(0);

banner = get_http_banner(port:port);
match = eregmatch(string:banner, pattern:".*Server: lighttpd/([0-9.]+).*", icase:TRUE);
if (isnull(match)) exit(0);

version = match[1];
if (isnull(version)) exit(0);
ver_fields = split(version, sep:".", keep:FALSE);
major = ver_fields[0];
minor = ver_fields[1];
rev = ver_fields[2];

if (
  major < 1 ||
  (major == 1 && minor < 4) ||
  (major == 1 && minor == 4 && rev < 23)
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "lighttpd version ", version, " appears to be installed on the remote host\n",
      "based on the following Server response header :\n",
      "\n",
      "  ", match, "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
