#
# This script was written by Audun Larsen <larsen@xqus.com>
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/3/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(12069);
 script_version("$Revision: 1.7 $");

 script_name(english:"SMC2804WBR Router Default Password (smcadmin)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote router can be accessed with default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote host is a SMC2804WBR access point.

This host is installed with a default administrator 
password (smcadmin) which has not been modifed.

An attacker may exploit this flaw to gain control over
this host using the default password." );
 script_set_attribute(attribute:"solution", value:
"Change the administrator password" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Logs in with default password on SMC2804WBR");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Audun Larsen");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);
res = http_get_cache(item:"/", port:port);
if( res == NULL ) exit(0);
if("SMC2804WBR" >< res && "Please enter correct password for Administrator Access. Thank you." >< res)
 {

  host = get_host_name();
  variables = string("page=login&pws=smcadmin");
  req = string("POST /login.htm HTTP/1.1\r\n", 
  	      "Host: ", host, ":", port, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);
  if("<title>LOGIN</title>" >< buf)
  {
  } else {
   security_hole(port);
   exit(0);
  } 
}

