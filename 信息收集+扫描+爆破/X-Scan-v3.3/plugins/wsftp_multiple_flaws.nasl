#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref : Hugh Mann <hughmann@hotmail.com>
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (2/03/2009)

include("compat.inc");

if(description)
{
 script_id(14598);
 script_version ("$Revision: 1.12 $");

 script_cve_id("CVE-2004-1848", "CVE-2004-1883", "CVE-2004-1884", "CVE-2004-1885");
 script_bugtraq_id(9953);
 script_xref(name:"OSVDB", value:"4539");
 script_xref(name:"OSVDB", value:"4540");
 script_xref(name:"OSVDB", value:"4541");
 script_xref(name:"OSVDB", value:"4542");
 script_xref(name:"OSVDB", value:"59291");

 script_name(english:"WS_FTP Server Multiple Vulnerabilities (OF, DoS, Cmd Exec)");
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP server has multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of WS_FTP running on the remote
host has multiple vulnerabilities, including :

  - A buffer overflow caused by a vulnerability in the ALLO handler.

  - A flaw which could allow an attacker to gain SYSTEM level
    privileges.

  - A local or remote attacker with write privileges on a directory
    can create a specially crafted file, causing a denial of service.

A remote attacker could exploit these vulnerabilities to execute
arbitrary code."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of WS_FTP."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
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

#

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if (egrep(pattern:"WS_FTP Server ([0-3]\.|4\.0[^0-9.]|4\.0\.[12][^0-9])", string: banner))
	security_hole(port);
