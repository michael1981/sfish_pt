#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12060);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2004-0282");
 script_bugtraq_id(9651);
 script_xref(name:"OSVDB", value:"6621");

 script_name(english:"Crob FTP Server Connection Saturation Remote DoS");
 script_summary(english:"Crob Remote DoS");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description",
   value:string(
     "According to its version number, the remote Crob FTP server has a\n",
     "denial of service vulnerability.  Repeatedly connecting and\n",
     "disconnecting causes the service to crash."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-02/0390.html"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to the latest version of Crob FTP server."
 );
 script_set_attribute(
   attribute:"cvss_vector",
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_require_ports("Services/ftp", 21);
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl");

 exit(0);
}

#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);


# 220-Crob FTP Server V3.5.2
#220 Welcome to Crob FTP Server.
if(egrep(pattern:"Crob FTP Server V(3\.([0-4]\..*|5\.[0-2])|[0-2]\..*)", string:banner)) security_warning(port);

