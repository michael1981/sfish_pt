#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20927);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-0705");
  script_bugtraq_id(16640);
  script_xref(name:"OSVDB", value:"23120");

  script_name(english:"SSH Tectia Server SFTP Filename Logging Format String");
  script_summary(english:"Checks for format string vulnerability in SSH Tectia Server SFTP subsystem");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server may be affected by a format string
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SSH Tectia Server, a commercial SSH server. 

According to its banner, the installed version of this software
contains a format string vulnerability in its sftp subsystem.  A
remote, authenticated attacker may be able to execute arbitrary code
on the affected host subject to his privileges or crash the server
itself." );
 script_set_attribute(attribute:"see_also", value:"http://www.ssh.com/company/newsroom/article/715/" );
 script_set_attribute(attribute:"solution", value:
"As a temporary solution, disable the sftp subsystem as described in
the vendor advisory above.  A better solution, though, is to upgrade
to SSH Tectia Server version 4.3.7 or 4.4.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("backport.inc");

port = get_kb_item("Services/ssh");
if (!port) port = 22;


banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);
banner = get_backport_banner(banner:banner);

if ( ereg(pattern:"^SSH-2\.0-([0-3]\..*|4\.([0-2]\..*|3\.[0-6]\..*|4\.[01]\..*)) SSH (Tectia Server|Secure Shell)", string:banner)
) {
  security_warning(port);
}
