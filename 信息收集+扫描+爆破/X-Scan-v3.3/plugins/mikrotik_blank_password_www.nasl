#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39420);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-1999-0508");

  script_name(english:"MikroTik RouterOS with Blank Password (HTTP)");
  script_summary(english:"Tries to log in as admin");

 script_set_attribute(attribute:"synopsis", value:
"The remote router has no password for its admin account." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MikroTik RouterOS without a password for
its 'admin' account.  Anyone can connect to it and gain administrative
access to it." );
 script_set_attribute(attribute:"see_also", value:"http://www.mikrotik.com/documentation.html" );
 script_set_attribute(attribute:"solution", value:
"Log in to the device and configure a password using the '/password'
command." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("httpver.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 8080);

page = http_get_cache(port: port, item: "/");
if ( '<input type="text" name="user"' >!< page ||
     '<input type="password" name="password">' >!< page ||
     '<input type="submit" name="" value="Connect">' >!< page)
  exit(0);

clear_cookiejar();
# Need to set a cookie
r = http_send_recv3(port: port, item:"/", method: "GET");
if (isnull(r)) exit(0);

user = "admin";
pass = "";
d = strcat("process=login&page=start&user=", user, "&password=", pass, "&=Connect");
r = http_send_recv3(method: "POST", item: "/main.html", port: port,
  add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
  data: d);
if (isnull(r)) exit(0);
if (r[0] !~ "^HTTP/1\.[01] 200 ") exit(0);
if ( '<form name="deviceForm" action="/main.html"' >< r[2] &&
     '<form name="networksForm" action="/main.html"' >< r[2])
  security_hole(port: port);
