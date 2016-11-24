#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# Modified by Paul Johnston for Westpoint Ltd to display the web root
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11393);
 script_bugtraq_id(4542);
 script_xref(name:"OSVDB", value:"3337");

 script_name(english:"ColdFusion on IIS cfm/dbm Diagnostic Error Path Disclosure");

 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2002-0576");
 script_xref(name:"OSVDB", value:"3337");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a path disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote web server disclose the 
physical path to its web root by requesting a MS-DOS device 
ending in .dbm (as in nul.dbm)." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0028.html" );
 script_set_attribute(attribute:"solution", value:
" The vendor suggests turning on 'Check that file exists' :

   Windows 2000:
   1. Open the Management console
   2. Click on 'Internet Information Services'
   3. Right-click on the website and select 'Properties'
   4. Select 'Home Directory'
   5. Click on 'Configuration'
   6. Select '.cfm'
   7. Click on 'Edit'
   8. Make sure 'Check that file exists' is checked
   9. Do the same for '.dbm'" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();


 script_summary(english:"Checks for a ColdFusion vulnerability");

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

#
# The script code starts here
#

port = get_http_port(default:80);

r = http_send_recv3(method:"GET", item:"/nul.dbm", port:port);
if (isnull(r)) exit(0);
res = strcat(r[0], r[1], '\r\n', r[2]);

webroot = eregmatch(pattern:"([A-Za-z]:\\[^<>]+\\)nul.dbm", string:res);
if(!isnull(webroot))
{
  report = string(
             "\n",
             "It is possible to make the remote web server disclose the \n",
             "physical path to its web root by requesting a MS-DOS device \n",
             "ending in .dbm (as in nul.dbm)",
             "\n",
             "The remote web root is : " + webroot[1] + "\n");

  security_warning(port:port, extra:report);
}
