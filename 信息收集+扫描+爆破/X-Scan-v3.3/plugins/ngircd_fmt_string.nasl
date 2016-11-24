#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16310);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-0226");
 script_bugtraq_id(12434);
 script_xref(name:"OSVDB", value:"13444");
 
 script_name(english:"ngIRCd < 0.8.3 Log_Resolver() Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote chat server is affected by a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of the ngIRCd chat service
running on the remote host contains a format string vulnerability.  If
it was compiled with IDENT, DEBUG is enabled, and it's logging to
SYSLOG, a remote attacker can leverage this issue to execute arbitrary
code on the remote host subject to the privileges under which the
service operates, which is 'root' by default." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110746413108183&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://ngircd.barton.de/doc/ChangeLog" );
 script_set_attribute(attribute:"see_also", value:"http://arthur.barton.de/pipermail/ngircd-ml/2005-February/000234.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ngIRCd 0.8.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 script_summary(english:"checks the version of the remote ircd");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("ircd.nasl");
 script_require_ports("Services/irc", 6667);
 exit(0);
}

#

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(! get_port_state(port)) exit(0);

key = string("irc/banner/", port);
banner = get_kb_item(key);
if(!banner)exit(0);

if(egrep(pattern:".*ngircd-0\.([0-7]\.|8\.[0-2][^0-9]).*", string:banner)) 
{
 security_hole(port);
 exit(0);
}
