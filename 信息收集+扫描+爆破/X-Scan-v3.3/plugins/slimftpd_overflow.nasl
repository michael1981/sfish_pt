#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15704);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2004-2418", "CVE-2005-2373");
 script_bugtraq_id(11645, 14339);
 script_xref(name:"OSVDB", value:"11604");
 script_xref(name:"OSVDB", value:"18172");
 
 script_name(english:"SlimFTPd Multiple Command Handling Overflow");
 script_summary(english:"Checks version in the banner");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote FTP server is prone to multiple buffer overflow attacks."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host appears to be using SlimFTPd, a free, small,\n",
   "standards-compliant FTP server for Windows. \n",
   "\n",
   "According to its banner, the version of SlimFTPd installed on the remote\n",
   "host is prone to one or more buffer overflow vulnerabilities that can\n",
   "lead to arbitrary code execution.  \n",
   "\n",
   "Note that successful exploitation of either of these flaws requires an\n",
   "attacker first authenticate."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-11/0293.html"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2005-07/0348.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to SlimFTPd version 3.17 or later."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;
if ( ! get_port_state(port) ) exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);


# There's a problem if...
if (
  # The version in the banner is <= 3.16 or...
  egrep(string:banner, pattern:"^220-SlimFTPd ([0-2]\.|3\.1[0-6][^0-9])")
) {
  security_hole(port);
}
