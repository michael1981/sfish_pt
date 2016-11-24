#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18588);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2085");
  script_bugtraq_id(14077);
  script_xref(name:"OSVDB", value:"17607");

  script_name(english:"Inframail SMTP MAIL FROM Command Remote Overflow DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the SMTP server component of Inframail, a
commercial suite of network servers from Infradig Systems. 

According to its banner, the installed version of Inframail suffers
from a buffer overflow vulnerability that arises when the SMTP server
component processes a MAIL FROM command with an excessively long
argument (around 40960 bytes).  Successful exploitation will cause the
service to crash and may allow arbitrary code execution." );
 script_set_attribute(attribute:"see_also", value:"http://reedarvin.thearvins.com/20050627-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-06/0348.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Inframail 7.12 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

  script_summary(english:"Checks for remote buffer overflow vulnerability in Inframail SMTP Server");
  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");
  exit(0);
}


include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


banner = get_smtp_banner(port:port);
if (banner && banner =~ "InfradigServers-MAIL \(([0-5]\..*|6.([0-2].*|3[0-7])) ")
  security_hole(port);
