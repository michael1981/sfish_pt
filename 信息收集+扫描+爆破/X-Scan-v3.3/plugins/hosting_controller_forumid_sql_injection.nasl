#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22902);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-5629");
  script_bugtraq_id(20661);
  script_xref(name:"OSVDB", value:"30157");
  script_xref(name:"OSVDB", value:"30156");

  script_name(english:"Hosting Controller Multiple Script ForumID Parameter SQL Injection");
  script_summary(english:"Checks for a SQL injection flaw in Hosting Controller");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is susceptible
to a SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The installed version of Hosting Controller fails to sanitize input to
the 'ForumID' parameter of the 'forum/HCSpecific/EnableForum.asp'
script before using it in database queries.  An unauthenticated
attacker may be able to leverage this issue to manipulate database
queries to reveal sensitive information, modify data, launch attacks
against the underlying database, etc. 

In addition, the 'DisableForum.asp' script is also vulnerable." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?954337d8" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80267a16" );
 script_set_attribute(attribute:"solution", value:
"Apply the Post Hotfix 3.3 Security Patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8077);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8077, embedded: 0);
if (!can_host_asp(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/hc", "/hosting_controller", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  exploit = string("'", SCRIPT_NAME);
  r = http_send_recv3(method:"GET", 
    item:string(
      dir, "/forum/HCSpecific/EnableForum.asp?",
      "action=enableforum&",
      "ForumID=", exploit
    ),
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    string("query expression 'ForumID='", SCRIPT_NAME) >< res &&
    egrep(pattern:"Microsoft OLE DB Provider for ODBC Drivers.+error '80040e14'", string:res)
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
