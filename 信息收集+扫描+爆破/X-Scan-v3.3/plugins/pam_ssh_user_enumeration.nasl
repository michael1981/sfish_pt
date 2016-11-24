#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38197);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1273");
  script_bugtraq_id(34333);
  script_xref(name:"Secunia", value:"34536");
  script_xref(name:"OSVDB", value:"53693");

  script_name(english:"pam_ssh Login Prompt Remote Username Enumeration");
  script_summary(english:"Checks if the server responds differently to invalid usernames");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host is running a SSH server with an information\n",
      "disclosure vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host is running a SSH server that responds differently to\n",
      "login attempts depending on whether or not a valid username is\n",
      "given. This is likely due to a vulnerable version of pam_ssh.\n",
      "A remote attacker could use this to enumerate valid usernames,\n",
      "which could be used to mount further attacks."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.gentoo.org/show_bug.cgi?id=263579"
  );
  script_set_attribute(
    attribute:"solution",
    value:"There is no known solution at this time."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


include("global_settings.inc");
include("ssh_func.inc");


port = get_kb_item("Services/ssh");
if (!port) port = 22;

function setup_ssh()
{
  local_var server_version, ret, payload;

  # Exchange protocol version identification strings with the server.
  init();
  server_version = ssh_exchange_identification();
  if (!server_version) exit(0);

  _ssh_server_version = server_version;

  # key exchange
  ret = ssh_kex2(server_version:server_version, nofingerprint:TRUE);
  if (ret != 0) exit(0);
  payload = putstring(buffer:"ssh-userauth");

  # code 5 (SSH_MSG_SERVICE_REQUEST)
  send_ssh_packet(payload:payload, code:raw_string(0x05));

  # code 6 (SSH_MSG_SERVICE_ACCEPT)
  payload = recv_ssh_packet();

  # Bail out if the server doesn't support the ssh-userauth service
  # (it's required in order to do the check in this plugin)
  if (ord(payload[0]) != 6) exit(0);
}

# Sends a SSH_MSG_USERAUTH_REQUEST and gets the response
#
function get_userauth_req_resp(user)
{
  local_var payload, response_code;
  response_code = NULL;

  if( ! get_port_state(port) ) exit(0);
  _ssh_socket = open_sock_tcp(port);
 if ( ! _ssh_socket ) exit(0);
  setup_ssh();

  # send...
  payload = string(
    putstring(buffer:user),
    putstring(buffer:"ssh-userauth"),
    putstring(buffer:"keyboard-interactive"),
    putstring(buffer:""),
    putstring(buffer:"")
  );
  send_ssh_packet(payload:payload, code:raw_int8(i:50));

  # ... and check response
  payload = recv_ssh_packet();
  if (isnull(payload)) exit(0);

  response_code = ord(payload[0]);

  close(_ssh_socket);
  
  return response_code;
}


#
# Script execution starts here
#

valid_user_resp = get_userauth_req_resp(user:"root");
invalid_user_resp = get_userauth_req_resp(user:SCRIPT_NAME);

if (valid_user_resp != invalid_user_resp) security_warning(port);
