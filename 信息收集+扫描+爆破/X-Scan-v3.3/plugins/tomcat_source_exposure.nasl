#
# This script was written by Felix Huber <huberfelix@webtopia.de>
#
# v. 1.00 (last update 24.09.02)
#
#
# Changes by Tenable: 
# - removed un-necessary requests
# - revised plugin title, added OSVDB ref (4/7/2009)

include("compat.inc");

if(description)
{
 script_id(11176);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2002-1148");
 script_bugtraq_id(5786);
 script_xref(name:"OSVDB", value:"8773");

 script_name(english:"Apache Tomcat Catalina org.apache.catalina.servlets.DefaultServlet Source Code Disclosure");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has an information disclosure vulnerability."
 );
 script_set_attribute(
   attribute:"description",
   value:
"The version of Apache Tomcat running on the remote host has an
information disclosure vulnerability.  It is possible to view source
code by using the default servlet :

  org.apache.catalina.servlets.DefaultServlet

A remote attacker could use this information to mount further
attacks.

This version of Tomcat reportedly has other vulnerabilities, though
Nessus has not checked for those issues."
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector",
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_summary(english:"Tomcat 4.x JSP Source Exposure");

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2009 Felix Huber");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

function check(sfx, port)
{
   local_var url, req, r;

   url = string("/servlet/org.apache.catalina.servlets.DefaultServlet", sfx);
   req = http_get(item:url, port:port);
   r = http_keepalive_send_recv(port:port, data:req);
   if( r == NULL ) exit(0);

   if("<%@" >< r){
       security_warning(port);
       exit(0);
      }
      
    if(" 200 OK" >< r)
    {
     if("Server: Apache Tomcat/4." >< r)
     {
                security_warning(port); 
                exit(0); 
      } 
    }
}


 
port = get_http_port(default:80);


if(!get_port_state(port))exit(0);





files = get_kb_list(string("www/",port, "/content/extensions/jsp"));
if(!isnull(files))
 {
  files = make_list(files);
  file = files[0];
 }
else file = "/index.jsp";

check(sfx:file, port:port);
