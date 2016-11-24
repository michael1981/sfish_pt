#
# written by Bekrar Chaouki - A.D.Consulting <bekrar@adconsulting.fr>
#
# Apache Tomcat Directory listing and file disclosure Vulnerabilities
#
#

include("compat.inc");

if(description)
{
 script_id(11438);
 script_bugtraq_id(6721);
 script_version ("$Revision: 1.13 $");
 
 script_cve_id("CVE-2003-0042");
 
 name["english"] = "Apache Tomcat Directory Listing and File disclosure";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information  
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"Apache Tomcat (prior to 3.3.1a) is prone to a directory listing 
and file disclosure vulnerability.
By requesting URLs containing a null character, remote attackers 
can list directories even with an index.html or other file is 
present, or obtain unprocessed source code for a JSP file." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Tomcat 4.1.18 or newer version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();


 summary["english"] = "Apache Tomcat Directory listing and File Disclosure Bugs";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003-2009 A.D.Consulting");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# Start
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
res = http_get_cache(item:"/", port:port);
if( res == NULL ) exit(0);

if(("Index of /" >< res)||("Directory Listing" >< res))exit(0);

req = str_replace(string:http_get(item:"/<REPLACEME>.jsp", port:port),
	          find:"<REPLACEME>",
		  replace:raw_string(0));

res = http_keepalive_send_recv(port:port, data:req);

if ( res == NULL ) exit(0);

if(("Index of /" >< res)||("Directory Listing" >< res))
 security_warning(port);
}
