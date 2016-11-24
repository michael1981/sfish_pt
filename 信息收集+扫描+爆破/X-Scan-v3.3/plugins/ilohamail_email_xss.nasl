#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18050);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-1120");
  script_bugtraq_id(13175);
  script_xref(name:"OSVDB", value:"15506");

  script_name(english:"IlohaMail read_message.php Attachment Multiple Field XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is subject to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"Based on its version number, the installation of IlohaMail on the
remote host does not properly sanitize attachment file names, MIME
media types, and HTML / text e-mail messages.  An attacker can exploit
these vulnerabilities by sending a specially-crafted message to a user
which, when read using an affected version of IlohaMail, will allow
him to execute arbitrary HTML and script code in the user's browser
within the context of the affected web site." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=304525" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IlohaMail version 0.8.14-rc3 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for email message cross-site scripting vulnerabilities in IlohaMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("ilohamail_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ilohamail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  # nb: versions 0.8.14-rc2 and earlier may be affected.
  if (ver =~ "^0\.([1-7].*|8\.([0-9]([^0-9]|$)|1([0-3]|4.*rc[12])))")
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
