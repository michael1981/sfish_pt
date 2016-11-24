#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11621);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0286");
 script_bugtraq_id(7549);
 script_xref(name:"OSVDB", value:"4638");

 script_name(english:"Snitz Forums 2000 < 3.4.03 register.asp Email Parameter SQL Injection");
 script_summary(english:"Determine if Snitz forums is vulnerable to a cmd exec flaw");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The discussion forum running on the remote web server has a SQL\n",
     "injection vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
      "The remote version of Snitz Forums 2000 is vulnerable to a SQL\n",
      "injection attack.  The 'Email' parameter of 'register.asp' is not\n",
      "sanitized before being used in a SQL query.  A remote attacker could\n",
      "exploit this to execute arbitrary SQL queries."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0067.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Snitz Forums 2000 version 3.4.03 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);


function mkreq(path)
{
 local_var data, req;
 data = "Refer=&Email=test%27example.org&Email2=&HideMail=0&ICQ=&YAHOO=&AIM=&Homepage=&Link1=&Link2=&Name=test&Password=test&Password-d=&Country=&Sig=&MEMBER_ID=&Submit1=Submit";
 req = string("POST ", path, "/register.asp?mode=DoIt HTTP/1.1\r
Host: ", get_host_name(), "\r
User-Agent: Mozilla/5.0 (X11; U; Linux i386; en-US; rv:1.3)\r
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,video/x-mng,image/png,image/jpeg,image/gif;q=0.2,*/*;q=0.1\r
Accept-Language: en-us,en;q=0.5\r
Accept-Encoding: gzip,deflate,compress;q=0.9\r
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r
Referer: http:/", get_host_name(), path, "/register.asp\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: ", strlen(data), "\r\n\r\n", data);
 return req;
}

		


foreach d ( cgi_dirs() )
{
 if ( is_cgi_installed_ka(item:d + "/register.asp", port:port) )
 {
 req = mkreq(path:d);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("HTTP/1.1 500" >< res && "Microsoft OLE DB Provider for SQL Server" >< res)
  {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
  }
 }
}
