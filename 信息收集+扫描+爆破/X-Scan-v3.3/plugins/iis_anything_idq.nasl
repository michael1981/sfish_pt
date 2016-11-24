#
# This script was written by Filipe Custodio <filipecustodio@yahoo.com>
#
# See the Nessus Scripts License for details
#
# Changes by rd :
# - description slightly modified to include a solution


include("compat.inc");

if(description)
{
 script_id(10492);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-2000-0071", "CVE-2000-0098", "CVE-2000-0302");
 script_bugtraq_id(1065);
 script_xref(name:"OSVDB", value:"391");

 script_name(english:"Microsoft IIS IDA/IDQ Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IIS web server is missing a security patch." );
 script_set_attribute(attribute:"description", value:
"The remote version of IIS is affected by two vulnerabilities :

- An information disclosure issue allows a remote attacker to obtain 
the real pathname of the document root by requesting nonexistent 
files with .ida or .idq extensions.

- An argument validation issue in the WebHits component lets a remote 
attacker read abitrary files on the remote server

The path disclosure issue has been reported to affect Microsoft Index 
Server as well." );
 script_set_attribute(attribute:"solution", value:
"Microsoft released a patch for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms00-006.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "Determines IIS IDA/IDQ Path Reveal vulnerability";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2009 Filipe Custodio");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);


sig = get_http_banner(port:port);
if ( "IIS" >!< sig ) exit(0);


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 
 req = http_get(item:"/anything.idq", port:port);
 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 str = egrep( pattern:"^<HTML>", string:r ) - "<HTML>";
 str = tolower(str);
  
 if ( egrep(pattern:"[a-z]\:\\.*anything",string:str) ) {
   security_warning( port:port );
 } else {
   req = http_get(item:"/anything.ida", port:port);
   soc = http_open_socket(port);
   if(!soc)exit(0);
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   str = egrep( pattern:"^<HTML>", string:r ) - "<HTML>";
   str = tolower(str);
   if ( egrep(pattern:"[a-z]\:\\.*anything", string:str) )
      security_warning( port:port );
   }
}
