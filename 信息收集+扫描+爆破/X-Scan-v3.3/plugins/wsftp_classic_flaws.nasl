#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref : Hobbit <hobbit@avian.org>
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title, added VDB refs, added mail list references (2/05/2009)

include("compat.inc");

if(description)
{
 script_id(14599);
 script_cve_id("CVE-1999-0017");
 script_bugtraq_id(6050, 6051);
 script_xref(name:"OSVDB", value:"71");
 script_xref(name:"OSVDB", value:"51744");
 script_version ("$Revision: 1.9 $");

 script_name(english:"WS_FTP Server Multiple Vulnerabilities (Bounce, PASV Hijacking)");
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP server has multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the remote WS_FTP server is
vulnerable to session hijacking during passive connections and to an
FTP bounce attack when a user submits a specially crafted FTP
command."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/1995_3/0047.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2002-10/0367.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of this software."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();
 
 summary["english"] = "Check WS_FTP server version";
  script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#now the code

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if (egrep(pattern:"WS_FTP Server ([0-2]\.|3\.(0\.|1\.[0-3][^0-9]))", string: banner))
	security_hole(port);
