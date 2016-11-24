#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11542);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(7380);
 script_xref(name:"OSVDB", value:"35707");
 
 script_name(english:"Web Wiz Forums wwforum.mdb Direct Request Database Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server is running Web Wiz Site Forum, a set of ASP scripts
to manage online forums. 

This release comes with a 'wwforum.mdb' database, usually located
under 'admin', that contains sensitive information, such as the user
passwords and emails.  An attacker may use this flaw to gain
unauthorized access to the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-04/0234.html" );
 script_set_attribute(attribute:"solution", value:
"Prevent the download of .mdb files from your website." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for wwforum.mdb");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_asp(port:port)) exit(0);


if (thorough_tests) dirs = list_uniq(make_list("/forums", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach d ( dirs )
{
 url = string(d, "/admin/wwforum.mdb");
 w = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(w)) exit(0);
 res = w[2];

 if("Standard Jet DB" >< res)
 {
  report = string(
   "\n",
   "The database is accessible via the following URL :\n",
   "\n",
   "  ", build_url(port:port, qs:url), "\n"
  );
  security_warning(port:port, extra:report);
  exit(0);
 }
}
