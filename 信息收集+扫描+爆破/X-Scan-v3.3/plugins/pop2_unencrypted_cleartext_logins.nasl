#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/3/09)


include("compat.inc");

if (description) {
  script_id(15854);
  script_version("$Revision: 1.5 $");

  script_name(english:"POP2 Cleartext Logins Permitted");

 script_set_attribute(attribute:"synopsis", value:
"The remote POP2 daemon allows credentials to be transmitted in clear 
text." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a POP2 daemon that allows cleartext logins over
unencrypted connections.  An attacker can uncover login names and
passwords by sniffing traffic to the POP2 daemon." );
 script_set_attribute(attribute:"solution", value:
"Encrypt traffic with SSL / TLS using stunnel." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );

script_end_attributes();

  script_summary(english:"Checks for unencrypted POP2 login capability");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 George A. Theall");
  script_family(english:"Misc.");
  script_dependencie("find_service1.nasl", "global_settings.nasl");
  script_require_ports("Services/pop2", 109);
  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/pop2");
if (!port) port = 109;
debug_print("checking if POP2 daemon on port ", port, " allows unencrypted cleartext logins.");
if (!get_port_state(port)) exit(0);
# nb: skip it if traffic is encrypted.
encaps = get_port_transport(port);
if (encaps >= ENCAPS_SSLv2) exit(0);

# Establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);
r = recv_line(socket:soc, length:4096);
if ( "POP" >!< r ) exit(0);

# nb: POP2 doesn't support encrypted logins so there's no need to
#     actually try to log in. [Heck, I probably don't even need to
#     establish a connection.]
security_note(port);

close(soc);
