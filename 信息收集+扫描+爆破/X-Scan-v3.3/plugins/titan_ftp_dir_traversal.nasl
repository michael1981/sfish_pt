#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: D4rkGr3y
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (2/03/2009)

include("compat.inc");

if(description)
{
 script_id(14659);
 script_version ("$Revision: 1.7 $");
 script_xref(name:"OSVDB", value:"9396");
 script_xref(name:"Secunia", value:"8914");

 script_name(english:"Titan FTP Server quote stat Command Traversal Arbitrary Directory Listing");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a directory traversal vulnerability."
 );
 script_set_attribute(
   attribute:"description",
   value:
"According to its banner, the version of Titan FTP Server running on
the remote host has a directory traversal vulnerability.  A remote
attacker could exploit this to view arbitrary files on the system."
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?f82b50d3 (researcher's advisory)"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector",
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();
 
 summary["english"] = "Check Titan FTP server version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#the code

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);

if (egrep(pattern:"^220.*Titan FTP Server ([0-1]\.|2\.0[12][^0-9])", string:banner) ) 
	security_warning(port);

