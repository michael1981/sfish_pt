#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(21607);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-2437", "CVE-2006-2438");
  script_bugtraq_id(18007);
  script_xref(name:"OSVDB", value:"25571");

  script_name(english:"Resin viewfile Servlet Arbitrary File Disclosure");
  script_summary(english:"Tries to get the absolute installation path of Resin");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to arbitrary file access." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Resin, an application server. 

The installation of Resin on the remote host includes a servlet, named
'viewfile', that lets an unauthenticated remote attacker view any file
within the web root directory on the affected host, which may lead to
a loss of confidentiality." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/434145/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.caucho.com/download/changes.xtp" );
 script_set_attribute(attribute:"solution", value:
"Either remove the 'resin-doc.war' file and do not deploy using default
configuration files or upgrade to Resin 3.0.19 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);

# Make sure the banner is from Resin.
banner = get_http_banner(port:port);
if (!banner || "Resin/" >!< banner) exit(0);


# Try to exploit the issue to request a nonexistent class file.
class = string("org/nessus/", SCRIPT_NAME, "/", unixtime(), ".class");
r = http_send_recv3(method:"GET", 
  item:string(
    "/resin-doc/viewfile/?",
    "contextpath=/&",
    "servletpath=&",
    "file=WEB-INF/classes/", class
  ), 
  port:port
);
if (isnull(r)) exit(0);
res = r[2];


# There's a problem if we get an error involving our class name with a full path.
#
# nb: 3.0.19 returns something like:
#     <b>File not found /WEB-INF/classes/org/nessus/resin_viewfile_file_access.nasl/1147831042.class</b></font>
if (
  "<b>File not found" &&
  egrep(pattern:string("found /.+/webapps/ROOT/WEB-INF/classes/", class, "<"), string:res)
) security_warning(port);
