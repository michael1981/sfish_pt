#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35820);
  script_version("$Revision: 1.2 $");

  script_name(english:"Thecus NAS Device Detection");
  script_summary(english:"Looks at initial web page");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host is a network-attached storage device."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "According to its web server, the remote host is a Thecus NAS (Network-\n",
      "Attached Storage) device, which provides file-based data storage to\n",
      "hosts across a network."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.thecus.com/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure the banner looks like a Thecus NAS device.
banner = get_http_banner(port:port);
if (banner && "Server: mini_httpd/" >< banner)
{
  # Check the initial page for evidence of Thecus.
  res = http_get_cache(item:"/", port:port);
  if (isnull(res)) exit(0);

  if (
    '<TITLE>Thecus NAS</TITLE>' >< res &&
    'NORESIZE SRC="/sys/cgi-bin/nas.cgi?choice=login?choice=login">' >< res
  ) security_note(0);
}
else if (banner && "Server: Apache" >< banner)
{
  # Check the initial page for evidence of a Thecus N5200.
  res = http_get_cache(item:"/", port:port);
  if (isnull(res)) exit(0);

  if (
    '<title>Thecus N5200' >< res &&
    'form method="POST" action="/usr/usrgetform.html?name=index"' >< res
  ) security_note(port:port, extra:'\nThe remote host seems to be a Thecus N5200.');
}
