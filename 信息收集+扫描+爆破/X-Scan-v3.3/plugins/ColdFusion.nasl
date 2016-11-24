#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_name(english:"ColdFusion Multiple Vulnerabilities (File Upload/Manipulation)");
 script_id(10001);
 script_xref(name:"IAVA", value:"1999-b-0001");
 script_bugtraq_id(115);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-1999-0455", "CVE-1999-0477");
 script_xref(name:"OSVDB", value:"1");
 script_xref(name:"OSVDB", value:"50620");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote application server is affected by multiple\n",
   "vulnerabilities."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The 'exprcalc.cfm' page in the version of Cold Fusion Application\n",
   "Server installed on the remote host allows an unauthenticated remote\n",
   "attacker to read arbitrary files on the remote host and possibly to\n",
   "delete or even upload arbitrary files as well."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/1999_2/0216.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Contact the vendor for a patch.\n",
   "\n",
   "In addition to this patch, it is recommended that the documentation\n",
   "and example code not be stored on production servers."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_summary(english:"Checks for a ColdFusion vulnerability");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

#
# The script code starts here
#

port = get_http_port(default:80);

cgi  = "/cfdocs/expeval/ExprCalc.cfm?OpenFilePath=c:\winnt\win.ini";
cgi2 = "/cfdocs/expeval/ExprCalc.cfm?OpenFilePath=c:\windows\win.ini";
y = is_cgi_installed3(item:cgi, port:port);
if(!y){
	y = is_cgi_installed3(item:cgi2, port:port);
	cgi = cgi2;
	}
	
	
if(y){
        res = http_send_recv3(method:"GET", item:cgi, port:port);
  	if ( isnull(res) ) exit(0);
	if( "[fonts]" >< res )
		security_hole(port);
	}
