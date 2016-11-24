#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(17593);
 script_cve_id("CVE-2005-0850", "CVE-2005-0851");
 script_bugtraq_id(12865);
 script_xref(name:"OSVDB", value:"14928");
 script_xref(name:"OSVDB", value:"14929");
 script_xref(name:"Secunia", value:"14664");
 script_version("$Revision: 1.7 $");

 script_name(english:"FileZilla FTP Server Multiple DoS");
 script_summary(english:"Determines the presence of FileZilla");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has multiple denial of service vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running a version of FileZilla server with the\n",
     "following denial of service vulnerabilities :\n\n",
     "  - Requesting a file containing the reserved name of a DOS\n",
     "    device (e.g. CON, NUL, COM1, etc.) can cause the\n",
     "    server to freeze.\n\n",
     "  - Downloading a file or directory listing with MODE Z\n",
     "    enabled (zlib compression) can cause an infinite loop."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://sourceforge.net/project/shownotes.php?release_id=314473"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to FileZilla Server 0.9.6 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 
 script_dependencies("ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if(egrep(pattern:"^220.*FileZilla Server version 0\.([0-8]\.|9\.[0-5][^0-9])", string:banner))
        security_hole(port);

