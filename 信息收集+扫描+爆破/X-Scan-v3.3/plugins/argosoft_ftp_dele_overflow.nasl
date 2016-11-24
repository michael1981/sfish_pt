#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17303);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-0696");
  script_bugtraq_id(12755);
  script_xref(name:"OSVDB", value:"14611");
 
  script_name(english:"ArGoSoft FTP Server DELE Command Remote Buffer Overrun");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow flaw." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of ArGoSoft FTP Server installed
on the remote host is affected by a heap buffer overflow that can be
triggered by a malicious user with delete rights who issues a DELE
command with an argument exceeding 2000 characters." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/426081/100/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for DELE command remote buffer overrun in ArGoSoft FTP Server");
  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencie("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  exit(0);
}


include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);
if (
  banner &&
  "ArGoSoft FTP Server" >< banner &&
  egrep(pattern:"^220[- ]ArGoSoft FTP Server.*Version.*\(1\.([0-3]\..*|4\.[0-1]|4\.2\.[0-8])", string:banner)
) security_warning(port);



