#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26058);
  script_version("$Revision: 1.5 $");

  script_name(english:"lighttpd Status Module Remote Information Disclosure");
  script_summary(english:"Sends requests for status urls");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
  script_set_attribute(attribute:"description", value:
"The installation of lighttpd on the remote host allow unauthenticated
access to URLs associated with the Status module (mod_status), at
least from the Nessus server.  Mod_status reports information about
how the web server is configured and its usage, and it may prove
useful to an attacker seeking to attack the server or host." );
  script_set_attribute(attribute:"see_also", value:"http://trac.lighttpd.net/trac/wiki/Docs%3AModStatus" );
  script_set_attribute(attribute:"solution", value:
"Reconfigure lighttpd to require authentication for the affected
URL(s), restrict access to them by IP address, or disable the Status
module itself." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_keys("www/lighttpd");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure the banner looks like lighttpd.
banner = get_http_banner(port:port);
if (
  !banner || 
  "lighttpd/" >!< banner
) exit(0);


# Try to retrieve the possible default URLs.
urls = make_list("/server-status", "/server-config", "/server-statistics");

info = "";
foreach url (urls)
{
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (
    ("status" >< url     && ">Server-Status<" >< res) ||
    ("config" >< url     && ">Server-Features<" >< res) ||
    ("statistics" >< url && "fastcgi.backend." >< res)
  )
  {
    info += '  ' + url + '\n';
    if (!thorough_tests) break;
  }
}


# Report any findings.
if (info)
{
  nurls = max_index(split(info));

  report = string(
    "Nessus found ", nurls, " URL(s) associated with the Status module enabled :\n",
    "\n",
    info
  );

  if (!thorough_tests)
  {
    report = string(
      report,
      "\n",
      "Note that Nessus did not check whether there were other instances\n",
      "installed because the Thorough Tests setting was not enabled when\n",
      "this scan was run.\n"
    );
  }

  security_warning(port:port, extra:report);
}
