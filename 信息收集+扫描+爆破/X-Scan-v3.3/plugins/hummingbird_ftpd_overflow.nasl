#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18402);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-1815");
  script_bugtraq_id(13790);
  script_xref(name:"OSVDB", value:"16956");

  script_name(english:"Hummingbird InetD FTP Component (ftpdw.exe) Command Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the ftpd daemon installed on the remote host
is from the Hummingbird Connectivity suite and suffers from a buffer
overflow vulnerability. An attacker can crash the daemon and possibly
execute arbitrary code remotely within the context of the affected
service." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83df6392" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

 script_end_attributes();
 
  script_summary(english:"Checks for buffer overflow vulnerability in Hummingbird ftpd");
  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# Use a banner check; it's not configurable.
banner = get_ftp_banner(port:port);
if (
  banner && 
  egrep(string:banner, pattern:"^220[- ] .+HCLFTPD\) Version ([0-9]\.|10\.0\.0\.0)\)")
) security_hole(port);

