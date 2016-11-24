#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20866);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-0504");
  script_bugtraq_id(16525);
  script_xref(name:"OSVDB", value:"23033");

  script_name(english:"MailEnable Webmail Malformed Quoted-printable Email DoS (CVE-2006-0504)");
  script_summary(english:"Checks for quoted-printable message denial of service vulnerability in MailEnable Webmail");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MailEnable, a commercial mail server for
Windows. 

According to its banner, using the webmail service bundled with the
version of MailEnable Enterprise Edition on the remote host to view
specially-formatted quoted-printable messages reportedly may result in
100% CPU utilization." );
 script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/enterprisehistory.asp" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MailEnable Enterprise Edition 1.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/smtp", 25, "Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("smtp_func.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# Make sure banner's from MailEnable.
banner = get_http_banner(port:port);
if (!banner || !egrep(pattern:"^Server: .*MailEnable", string:banner)) exit(0);


# Check the version number from the SMTP server's banner.
smtp_port = get_kb_item("Services/smtp");
if (!smtp_port) smtp_port = 25;
if (!get_port_state(smtp_port)) exit(0);
if (get_kb_item('SMTP/'+smtp_port+'/broken')) exit(0);

banner = get_smtp_banner(port:smtp_port);
if (
  banner && 
  banner =~ "Mail(Enable| Enable SMTP) Service"
) {
  # nb: Standard Edition seems to format version as "1.71--" (for 1.71),
  #     Professional Edition formats it like "0-1.2-" (for 1.2), and
  #     Enterprise Edition formats it like "0--1.1" (for 1.1).
  ver = eregmatch(pattern:"Version: (0-+)?([0-9][^- ]+)-*", string:banner);
  if (!isnull(ver)) {
    if (ver[1] == NULL) edition = "Standard";
    else if (ver[1] == "0-") edition = "Professional";
    else if (ver[1] == "0--") edition = "Enterprise";
  }
  if (isnull(ver) || isnull(edition)) {
    exit(1, "cannot determine edition of MailEnable's SMTP connector service");
  }
  ver = ver[2];

  # nb: Enterprise Edition versions < 1.2 are vulnerable.
  if (edition == "Enterprise" && ver =~ "^1\.[0-1]([^0-9]|$)") {
    security_warning(port);
  }
}
