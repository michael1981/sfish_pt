#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35700);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0641");
  script_bugtraq_id(33777);
  script_xref(name:"OSVDB", value:"52315");
  script_xref(name:"milw0rm", value:"8055");

  script_name(english:"FreeBSD telnetd sys_term.c Environment Variable Handling Privilege Escalation (FreeBSD-SA-09:05)");
  script_summary(english:"Tries to pass LD_DUMP_REL_POST=1 when calling login");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote telnet server is vulnerable to a code execution attack."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "A flaw in the environment-handling code used by the telnet server\n",
      "running on the remote host fails to scrub the environment of variables\n",
      "such as 'LD_PRELOAD' before calling the login program.  An attacker\n",
      "who can place an arbitrary library on the remote host, either as a\n",
      "local user or remotely through some other means, can leverage this\n",
      "issue to execute arbitrary code subject to the privileges under which\n",
      "the service runs, typically 'root'.\n"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://security.freebsd.org/advisories/FreeBSD-SA-09:05.telnetd.asc"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-02/0152.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Patch or upgrade the affected system as described in the project's\n",
      "advisory above."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/telnet", 23);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("telnet2_func.inc");


port = get_kb_item("Services/telnet");
if (!port) port = 23;
if (!get_port_state(port)) exit(0);


global_var rcvdata;


function telnet_callback()
{
  local_var data;

  data = _FCT_ANON_ARGS[0];

  # Accumulate each byte as it's received.
  if (data && ord(data[0]) != 0x00 && ord(data[0]) != 0x0d) rcvdata += data[0];

  # There's a problem if we were able to see info about symbol 
  # bindings and relocations.
  if (
    'login", relocbase ' >< rcvdata &&
    'libbz2.so", relocbase ' >< rcvdata
  )
  {
    security_hole(port);
    exit(0);
  }
  if ("login: " >< rcvdata)
  {
    exit(0);
  }
}


# Set up the environment.
env_data = 
  mkbyte(0) +
  mkbyte(3) + "LD_DUMP_REL_POST" +
    mkbyte(1) + "1" +
  mkbyte(3) + "LD_PRELOAD" +
    mkbyte(1) + "/usr/lib/libbz2.so" +
  mkbyte(0) + "USER" +
    mkbyte(1) + "nessus";

options = NULL;
options[0] = make_list(OPT_NEW_ENV, env_data);


# Connect and process options.
if (!telnet2_init(port:port, options:options, timeout:5*get_read_timeout()))
  exit(0);

rcvdata = NULL;
telnet_loop();
