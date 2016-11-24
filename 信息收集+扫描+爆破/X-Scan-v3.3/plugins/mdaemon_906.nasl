#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22256);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-4364");
  script_bugtraq_id(19651);
  script_xref(name:"OSVDB", value:"28125");

  script_name(english:"MDaemon < 9.0.6 POP3 Server USER / APOP Command Remote Overflow");
  script_summary(english:"Checks version of MDaemon POP3 Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote POP3 server is affected by multiple buffer overflow flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Alt-N MDaemon, a mail server for Windows. 

According to its banner, the POP3 server bundled with the version of
MDaemon on the remote host has two buffer overflows that can be
triggered with long arguments to the 'USER' and 'APOP' commands.  By
exploiting these issues, a remote, unauthenticated user can reportedly
crash the affected service or run arbitrary code with LOCAL SYSTEM
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.infigo.hr/en/in_focus/advisories/INFIGO-2006-08-04" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/444015/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://files.altn.com/MDaemon/Release/RelNotes_en.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MDaemon version 9.0.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/pop3", 110);
  exit(0);
}


include("pop3_func.inc");


port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);


# Do a banner check.
banner = get_pop3_banner(port:port);
if (
  banner &&
  " POP MDaemon " >< banner && 
  egrep(pattern:" POP MDaemon( ready using UNREGISTERED SOFTWARE)? ([0-8]\.|9\.0\.[0-5][^0-9])", string:banner)
) security_warning(port);
