#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(21245);
  script_version("$Revision: 1.9 $");

  script_name(english:"GDB Server Detection");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running gdbserver, a program which can be used to run
the GDB debugger on a different machine than the one which is running the
program being debugged.

Since gdbserver offers no authentication whatsoever, an attacker may connect
to this port, change the value of the registers and the memory of the process
being debugged, and therefore be able to execute arbitrary code on the remote
host with the privileges of the process being debugged." );
 script_set_attribute(attribute:"see_also", value:"http://sources.redhat.com/gdb/current/onlinedocs/gdb_18.html#SEC162" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port or disable this service" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_summary(english:"Detects the remote gdb server");
  script_dependencies("find_service2.nasl", "dcetest.nasl");
  script_require_ports("Services/unknown");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

if ( ! thorough_tests || get_kb_item("global_settings/disable_service_discovery")  ) exit(0);

port = get_unknown_svc();
if ( ! port ) exit(0);
# This is a silent_service()

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:'+$Hc-1#09');
r = recv(socket:soc, length:9);
close(soc);
if ( strlen(r) < 4 ) exit(0);
if ( substr(r, 0, 3) == '+$OK' ) security_hole(port);
