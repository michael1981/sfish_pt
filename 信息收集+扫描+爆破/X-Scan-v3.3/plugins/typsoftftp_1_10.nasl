#
# This script was written by Audun Larsen <larsen@xqus.com>
#
# Changes by Tenable:
# - Revised plugin title (2/03/2009)

include("compat.inc");

if(description)
{
 script_id(12075);
 script_cve_id("CVE-2004-0325");
 script_bugtraq_id(9702);
 script_xref(name:"OSVDB", value:"4058");
 script_version("$Revision: 1.10 $");

 script_name(english:"TYPSoft FTP Server 1.10 Invalid Path Request DoS");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP service has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description",
   value:
"The remote host appears to be running TYPSoft FTP server.  According
to its banner, this version of the software has a denial of service
vulnerability that can lead to complete exhaustion of CPU resources."
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-02/0617.html"
 );
 script_set_attribute(
   attribute:"solution",
   value:"There is no known solution at this time."
 );
 script_set_attribute(
   attribute:"cvss_vector",
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 summary["english"] = "Checks for version of TYPSoft FTP server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Audun Larsen");
 script_family(english:"FTP");
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
   banner = get_ftp_banner(port:port);
   if ( ! banner ) exit(0);
   if(egrep(pattern:".*TYPSoft FTP Server (0\.|1\.[0-9][^0-9]|1\.10[^0-9])", string:banner) )
    security_hole(port);
}

