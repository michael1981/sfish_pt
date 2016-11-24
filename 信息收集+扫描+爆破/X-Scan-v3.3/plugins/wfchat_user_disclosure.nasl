#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(11688);
 script_version ("$Revision: 1.16 $");

 script_cve_id("CVE-2003-1540");
 script_bugtraq_id(7147);
 script_xref(name:"OSVDB", value:"59645");

 name["english"] = "WF-Chat User Account Disclosure";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is prone to an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The WF-Chat allows an attacker to view information about registered
users by requesting the files '!nicks.txt' and '!pwds.txt'." );
 script_set_attribute(attribute:"see_also", value:"http://lists.insecure.org/lists/bugtraq/2003/Mar/0271.html" );
 script_set_attribute(attribute:"solution", value:
"Delete this CGI." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_end_attributes();
 
 summary["english"] = "Checks for the presence of !pwds.txt";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}
#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (get_kb_item("www/no404/"+port)) exit(0);

dirs = list_uniq(make_list("/chat", cgi_dirs()));
foreach dir (dirs)
{
 req = http_get(item:dir + "/!pwds.txt", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( isnull(res) ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res))
 {
  idx = stridx(res, string("\r\n\r\n"));
  if ( idx < 0 ) exit(0);
  data = substr(res, idx, strlen(res) - 1);
  notme = egrep(pattern:"^[^ ].*$", string:data);
  if(notme == NULL ){
   req = http_get(item:dir + "/chatlog.txt", port:port);
   res = http_keepalive_send_recv(port:port, data:req);
   if(isnull(res)) exit(0);
   if(egrep(pattern:"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ .[0-9].*", string:res))
   {
   security_warning(port);
   exit(0);
   }
  }
 }
}
