#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18354);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-1714");
  script_bugtraq_id(13689);
  script_xref(name:"OSVDB", value:"16690");

  script_name(english:"SurgeMail <= 3.0c2 Multiple XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is vulnerable to multiple cross-site scripting
attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running SurgeMail version
3.0c2 or earlier.  These versions reportedly are prone to multiple
cross-site scripting issues, which an attacker could exploit to inject
arbitrary HTML and script code into a user's browser to be processed
within the context of the affected website." );
 script_set_attribute(attribute:"see_also", value:"http://www.netwinsite.com/surgemail/help/updates.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SurgeMail 3.2e1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in SurgeMail <= 3.0c2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/smtp", 25, "Services/www", 7080);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("smtp_func.inc");


# Make sure the banner indicates it's from SurgeMail.
port = get_http_port(default:7080);
if (!get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if (!banner || "DManager" >!< banner) exit(0);


# Unfortunately, the web server doesn't include its version in the 
# Server response header so let's pull it from the SMTP server.
smtpport = get_kb_item("Services/smtp");
if (!smtpport) smtpport = 25;
banner = get_smtp_banner(port:smtpport);
if (banner) {
  ver = ereg_replace(
    string:banner, 
    pattern:"^[0-9][0-9][0-9] .* SurgeSMTP \(Version ([^)]+).+",
    replace:"\1"
  );

  # There's a problem if it's 3.0c2 or earlier.
  if (ver && ver =~ "^([0-2]\.|3\.0([ab]|c([0-2]|$)))") 
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
