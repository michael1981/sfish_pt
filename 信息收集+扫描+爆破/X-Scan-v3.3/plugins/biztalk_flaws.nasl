#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11638);
 script_bugtraq_id(7469, 7470);
 script_cve_id("CVE-2003-0117", "CVE-2003-0118");
 script_xref(name:"OSVDB", value:"10103");
 script_xref(name:"OSVDB", value:"10104");
 script_xref(name:"OSVDB", value:"13406");
 script_xref(name:"Secunia", value:"8707");

 script_version ("$Revision: 1.16 $");

 script_name(english:"Microsoft BizTalk Server Multiple Remote Vulnerabilities");
 script_summary(english:"Determines if BizTalk is installed");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote business process management service has multiple\n",
     "vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host seems to be running Microsoft BizTalk server.\n\n",
     "There are two flaws in this software which may allow an attacker\n",
     "to issue an SQL insertion attack or to execute arbitrary code on\n",
     "the remote host.\n\n",
     "*** Nessus solely relied on the presence of Biztalk to issue\n",
     "*** this alert, so this might be a false positive."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.microsoft.com/technet/security/bulletin/MS03-016.mspx"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Apply the relevant patches referenced in Microsoft Security\n",
     "Bulletin MS03-016."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if (thorough_tests)
  dirs = get_kb_list(string("www/", port, "/content/directories"));
if(isnull(dirs))dirs = make_list();
dirs = list_uniq(make_list(dirs, cgi_dirs()));
	
foreach d (dirs)
{
 if ( is_cgi_installed3(item:d + "/biztalkhttpreceive.dll", port:port) ) 
 {
   rq = http_mk_post_req( port: port, data: rand_str(length: 8),
       			  item: d+"/biztalkhttpreceive.dll");
   r = http_send_recv_req(port: port, req: rq);
   if (isnull(r)) exit(0);
 
 #
 # We might do multiple retries as the CGI sometimes stalls
 # when it has received a bad request first.
 # 
    if("HTTP/1.1 100 Continue" >< r[0] )
    { 
      end = 1;
      if(strlen(r[2]) == 0) end = 3;
      for (i = 0; i < end; i ++)
      {
 	if ("HTTP/1.1 500 Internal Server Error" >< r[0])
	{
	  security_hole(port);
	  exit(0);
	}
	r = http_send_recv_req(port:port, req: rq);	
	if(i + 1 < end) sleep(1);
      }
    }
 }
}
