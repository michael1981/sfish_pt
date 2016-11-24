#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14325);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(10982);
 script_cve_id("CVE-2007-0543");
 script_xref(name:"OSVDB", value:"9108");

 script_name(english:"ZixForum ZixForum.mdb DIrect Request Database Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that allows for
information disclosure." );
 script_set_attribute(attribute:"description", value:
"The remote server is running ZixForum, a set of ASP scripts for a
web-based forum. 

This program uses a database named 'ZixForum.mdb' that can be
downloaded by any client.  This database contains discussions, account
information, etc." );
 script_set_attribute(attribute:"solution", value:
"Prevent the download of .mdb files from the remote website." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 
 summary["english"] = "Checks for ZixForum.mdb";
 
 script_summary(english:summary["english"]);
 
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

if (thorough_tests) dirs = list_uniq(make_list("/zixforum", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach d ( dirs )
{
 url = string(d, "/news.mdb");
 r = http_send_recv3(method: "GET", item:url, port:port);
 if (isnull(r)) exit(0);
 
 if("Standard Jet DB" >< r[2])
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
