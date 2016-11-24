#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/21/009)


include("compat.inc");

if (description) {
  script_id(13648);
  script_version ("$Revision: 1.8 $");

  script_cve_id("CVE-2004-0613");
  script_bugtraq_id(10586);
  script_xref(name:"OSVDB", value:"15693");

  script_name(english:"osTicket Arbitrary Attachment Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"Sensitive data may be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of osTicket that enables a
remote user to view attachments associated with any existing ticket. 
These attachments may contain sensitive information." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to osTicket STS 1.2.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for Attachment Viewing Vulnerability in osTicket";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2009 George A. Theall");

  script_family(english:"CGI abuses");

  script_dependencie("global_settings.nasl", "http_version.nasl", "no404.nasl", "osticket_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for attachment viewing vulnerability in osTicket on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/osticket"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # Try to browse osTicket's attachments directory.
    url = string(dir, "/attachments/");
    if (debug_level) display("debug: checking ", url, ".\n");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    # If successful, there's a problem.
    if (ereg(pattern:"200 OK", string:res, icase:TRUE) && "[DIR]" >< res ) {
      security_warning(port:port);
      exit(0);
    }
  }
}
