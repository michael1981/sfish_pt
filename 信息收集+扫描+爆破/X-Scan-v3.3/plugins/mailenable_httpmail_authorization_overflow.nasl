#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description) {
  script_id(18123);
  script_version("$Revision: 1.5 $");

  script_bugtraq_id(13350);
  script_xref(name:"OSVDB", value:"15737");

  script_name(english:"MailEnable HTTPMail Service Authorization Header Remote Overflow");
  script_summary(english:"Checks for Authorization Buffer Overflow Vulnerability in MailEnable HTTPMail Service");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "A web application on the remote host has a buffer overflow\n",
      "vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of MailEnable running on the remote host has a buffer\n",
      "overflow vulnerability when processing the Authorization field in\n",
      "the HTTP header.  A remote attacker could exploit this to execute\n",
      "arbitrary code."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0408.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to the latest version of this software."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);
auth = make_array("Authorization", crap(data:"A", length:5));
buf = http_send_recv3(method:"GET", item:'/', add_headers:auth, port:port);
if (isnull(buf)) exit(1, "The server did not respond.");

if (("HTTP/1.1 401 Access Denied" >!< buf[0]) || ("Server: MailEnable-HTTP/5.0" >!< buf[1]))
  exit (0);

auth = make_array("Authorization", crap(data:"A", length:280));
buf = http_send_recv3(method:"GET", item:'/', add_headers:auth, port:port);
if (isnull(buf)) exit(1, "The server did not respond.");

if (("HTTP/1.1 401 Access Denied" >!< buf[0]) || ("Server: MailEnable-HTTP/5.0" >!< buf[1]))
  security_hole (port);
