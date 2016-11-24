#
# This script was written by Felix Huber <huberfelix@webtopia.de>
#
# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# Changes by gareth@sensepost.com (SensePost) :
# * Test all discovered directories for jsp bug


include("compat.inc");

if(description)
{
 script_id(10814);
 script_cve_id("CVE-2001-1510");
 script_bugtraq_id(3592);
 script_xref(name:"OSVDB", value:"680");

 script_version ("$Revision: 1.25 $");

 script_name(english:"Allaire JRun Encoded JSP Request Arbitrary Directory Listing");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information  
disclosure vulnerability" );
 script_set_attribute(attribute:"description", value:
"Allaire JRun 3.0/3.1 under a Microsoft IIS 4.0/5.0 platform has a
problem handling malformed URLs. This allows a remote user to browse
the file system under the web root (normally \inetpub\wwwroot).

Under Windows NT/2000(any service pack) and IIS 4.0/5.0:
- JRun 3.0 (all editions)
- JRun 3.1 (all editions)


Upon sending a specially formed request to the web server, containing
a '.jsp' extension makes the JRun handle the request. Example:

http://www.victim.com/%3f.jsp

This vulnerability allows anyone with remote access to the web server
to browse it and any directory within the web root." );
 script_set_attribute(attribute:"solution", value:
"From Macromedia Product Security Bulletin (MPSB01-13)
http://www.allaire.com/handlers/index.cfm?ID=22236&Method=Full

Macromedia recommends, as a best practice, turning off directory
browsing for the JRun Default Server in the following applications:
- Default Application (the application with '/' mapping that causes
  the security problem)

- Demo Application
  Also, make sure any newly created web application that uses the '/'
  mapping has directory browsing off.

The changes that need to be made in the JRun Management Console or JMC:

- JRun Default Server/Web Applications/Default User Application/File
  Settings/Directory Browsing Allowed set to FALSE.
- JRun Default Server/Web Applications/JRun Demo/File Settings/
  Directory Browsing Allowed set to FALSE.

Restart the servers after making the changes and the %3f.jsp request
should now return a 403 forbidden. When this bug is fixed, the request
(regardless of directory browsing setting) should return a '404 page
not found'.

The directory browsing property is called [file.browsedirs]. Changing
the property via the JMC will cause the following changes:
JRun 3.0 will write [file.browsedirs=false] in the local.properties
file. (server-wide change)
JRun 3.1 will write [file.browsedirs=false] in the webapp.properties
of the application." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 summary["english"] = "Allaire JRun directory browsing vulnerability";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001-2009 Felix Huber");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "DDI_Directory_Scanner.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(! port || !get_port_state(port))exit(0);

if (! thorough_tests)
dirs = get_kb_list(string("www/", port, "/content/directories"));
if(isnull(dirs))dirs = make_list("/", "/images", "/html"); # just some default dirs

 dirs = list_uniq(make_list(dirs, cgi_dirs()));

foreach d (dirs)
{
 req = http_get(item:string(d+"/%3f.jsp"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if(r == NULL) exit(0);

 if(egrep(pattern:"Index of /", string:r)||(egrep(pattern:"Directory Listing", string:r))) ddir += d + '\n';
}
if(ddir != NULL)
{
    report = "
The following directories were found to be browsable:
" +ddir;
    security_warning(port:port, extra:report);

}
