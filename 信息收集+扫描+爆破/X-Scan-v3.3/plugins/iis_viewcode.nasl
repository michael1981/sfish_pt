#
# This script was written by John Lampe (j_lampe@bellsouth.net)
#
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if(description)
{
  script_id(10576);
  script_cve_id("CVE-1999-0737");
  script_bugtraq_id(167);
  script_xref(name:"OSVDB", value:"474");
  script_version ("$Revision: 1.28 $");

  script_name(english:"Microsoft IIS / Site Server viewcode.asp Arbitrary File Access");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The file viewcode.asp is a default IIS files which can give a 
malicious user a lot of unnecessary information about your file 
system or source files.  Specifically, viewcode.asp can allow a
remote user to potentially read any file on a webserver hard drive." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/MS99-013.mspx" );
 script_set_attribute(attribute:"solution", value:
"If you do not need these files, then delete them, otherwise
use suitable access control lists to ensure that the files are not
world-readable." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

  script_summary(english:"Check for existence of viewcode.asp");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"(C) 2000-2009 John Lampe <j_lampe@bellsouth.net>");
  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);   
  exit(0);
}



#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);
	
	
fl[0] = "/Sites/Knowledge/Membership/Inspired/ViewCode.asp";
fl[1] = "/Sites/Knowledge/Membership/Inspiredtutorial/Viewcode.asp";
fl[2] = "/Sites/Samples/Knowledge/Membership/Inspired/ViewCode.asp";
fl[3] = "/Sites/Samples/Knowledge/Membership/Inspiredtutorial/ViewCode.asp";
fl[4] = "/Sites/Samples/Knowledge/Push/ViewCode.asp";
fl[5] = "/Sites/Samples/Knowledge/Search/ViewCode.asp";
fl[6] = "/SiteServer/Publishing/viewcode.asp";
   

list = "";

for(i=0;fl[i];i=i+1)
{ 
 url = fl[i];
 if(is_cgi_installed_ka(item:url, port:port))
  {
   list = string(list, "\n", url);
  }
 }
  
if(strlen(list))
{
 mywarning = string("The following files were found on the remote\n",
 			"web server : ", list, 
  	 		"\nThese files allow anyone to read arbitrary files on the remote host\n",
    		"Example, http://your.url.com/pathto/viewcode.asp?source=../../../../autoexec.bat\n",
    		"\n\nSolution : delete these files\n",
    		"Risk factor : High");
 security_warning(port:port, extra:mywarning);
 }


