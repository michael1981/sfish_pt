#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(18140);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-1282", "CVE-2005-1283", "CVE-2005-1284");
  script_bugtraq_id(13323, 13326);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15822");
    script_xref(name:"OSVDB", value:"15823");
    script_xref(name:"OSVDB", value:"15821");
    script_xref(name:"OSVDB", value:"15820");
  }

  name["english"] = "ArGoSoft Mail Server Pro <= 1.8.7.6 Multiple Vulnerabilities (XSS, Traversal, Priv Esc)";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The version of ArGoSoft Mail Server Pro installed on the remote host
suffers from several vulnerabilities, including :

  - Unauthenticated Account Creation Vulnerability
    The application does not authenticate requests sent through
    the web interface before creating mail accounts and may
    create them even if ArGoSoft has been configured not to.

  - Multiple Cross-Site Scripting Vulnerabilities
    ArGoSoft fails to filter some HTML tags in email messages;
    eg, the SRC parameter in an IMG tag. An attacker may be
    able to run arbitrary HTML and script code in a user's 
    browser within the context of the affected web site if 
    the user reads email using ArGoSoft's web interface." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/396694" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ArGoSoft Mail Server Pro 1.8.7.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in ArGoSoft Mail Server Pro <= 1.8.7.6";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# Make sure the server's banner indicates it's from ArGoSoft Mail Server.
port = get_http_port(default:80);
banner = get_http_banner(port:port);
if (!banner || "Server: ArGoSoft Mail Server" >!< banner) exit(0);


# Check for the vulnerability.
#
# - if safe checks are enabled...
if (safe_checks()) {
  # Test the version number.
  if (egrep(pattern:"^Server: ArGoSoft .+ \((0|1\.([0-7]|8\.([0-6]|7\.[0-6])))", string:banner)) {
    report = string(
      "Note that Nessus has determined the vulnerability exists on the\n",
      "remote host simply by looking at the version number of ArGoSoft\n",
      "installed there.\n"
    );
    security_warning(port:port, extra:report);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
# - otherwise, try to create an account
else {
  # Specify a user / password to create. gettimeofday() serves
  # to avoid conflicts and have a (somewhat) random password.
  now = split(gettimeofday(), sep:".", keep:0);
  user = string("nessus", now[0]);
  pass = now[1];

  postdata = string("username=", user, "&password=", pass, "&password1=", pass, "&submit=Add");
  r = http_send_recv3(method:"POST", item: "/addnew", port: port,
   add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
   data: postdata );
  if (isnull(r)) exit(0);
  res = r[2];
  if (egrep(string:res, pattern:"User has been successfully added.", icase:TRUE)) {
    report = string(
      "Nessus has successfully exploited this vulnerability by adding the\n",
      "user ", user, " to ArGoSoft on the remote host; you may wish to\n",
      "remove it at your convenience.\n"
    );
    security_warning(port:port, extra:report);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
