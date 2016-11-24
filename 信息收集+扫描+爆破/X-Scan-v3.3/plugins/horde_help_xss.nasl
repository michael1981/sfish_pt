#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title (4/30/09)


include("compat.inc");

if (description) {
  script_id(15605);
  script_version ("$Revision: 1.10 $"); 

  script_cve_id("CVE-2004-2741");
  script_bugtraq_id(11546);
  script_xref(name:"OSVDB", value:"11164");

  script_name(english:"Horde Application Framework Help Window Multiple Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of Horde in which the
help subsystem is vulnerable to a cross site scripting attack since
information passed to the help window is not properly sanitized." );
 script_set_attribute(attribute:"see_also", value:"http://lists.horde.org/archives/announce/2004/000107.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Horde version 2.2.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
  summary["english"] = "Checks for Help Subsystem XSS flaw in Horde";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2009 George A. Theall");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "horde_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (debug_level) display("debug: searching for Help Subsystem XSS flaw in Horde on ", host, ":", port, ".\n");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/horde"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    url = string(
      dir, 
      # nb: if you change the URL, you probably need to change the 
      #     pattern in the egrep() below.
      "/help.php?show=index&module=nessus%22%3E%3Cframe%20src=%22javascript:alert(42)%22%20"
    );
    if (debug_level) display("debug: retrieving ", url, "...\n");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (isnull(res)) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    if (egrep(string:res, pattern:'frame src="javascript:alert')) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
