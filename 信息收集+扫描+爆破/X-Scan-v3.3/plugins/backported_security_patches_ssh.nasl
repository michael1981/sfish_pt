#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(39520);
 script_version ("$Revision: 1.4 $");
 
 script_name(english: "Backported Security Patch Detection (SSH)");
 
 script_set_attribute(attribute:"synopsis", value:
"Security patches are backported." );
 script_set_attribute(attribute:"description", value:
"Security patches may have been 'back ported' to the remote SSH server
without changing its version number. 

Banner-based checks have been disabled to avoid false positives.

Note that this test is informational only and does not denote any 
security problem." );
 script_set_attribute(attribute:"solution", value: "N/A" );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?d636c8c7" );
 script_end_attributes();

 script_summary(english: "Backported security patches");
 script_category(ACT_END);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "General");
 script_dependencie("global_settings.nasl", "ssh_detect.nasl");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("backport.inc");

port = get_kb_item("Services/ssh");
if (! port) port = 22;
if (! get_port_state(port)) exit(0);

banner = get_kb_item("SSH/banner/"+port);
if (strlen(banner) == 0) exit(0);

backported = 0;
banner2 = get_backport_banner(banner:banner);
if (banner != banner2)
  if (get_kb_item("Host/local_checks_enabled"))
    security_note(port: port);
  else
    security_note(port: port, extra: "Give Nessus credentials to perform local checks.");
