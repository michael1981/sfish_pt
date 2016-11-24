#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11783);
 script_version ("$Revision: 1.8 $");

 script_cve_id("CVE-2003-0478");
 script_bugtraq_id(8038);
 script_xref(name:"OSVDB", value:"11827");
 script_xref(name:"OSVDB", value:"58937");
 script_xref(name:"OSVDB", value:"58938");
 script_xref(name:"OSVDB", value:"58939");
 script_xref(name:"OSVDB", value:"58940");
 
 script_name(english:"Multiple Vendor IRC Daemon Debug Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote chat server is affected by a remote command execution
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of ircd which may be vulnerable
to a format string attack.

An attacker may use this flaw to execute arbitrary code on this
host, or simply to disable this service remotely." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=105665996104723&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=105673555726823&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=105673489525906&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to one of the following IRC daemon :
andromede.net AndromedeIRCd 1.2.4
DALnet Bahamut IRCd 1.4.36
digatech digatech IRCd 1.2.2
methane methane IRCd 0.1.2" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"checks the version of the remote ircd");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "find_service2.nasl", "ircd.nasl");
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

if(egrep(pattern:".* bahamut-(0\.|1\.[0-3][^0-9]|1\.4.([0-9][^0-9]|[0-2][0-9]|3[0-5]))", string:banner))
{
 security_hole(port);
 exit(0);
}

# : AndromedeIRCd-1.3(00). 

if(egrep(pattern:".*AndromedeIRCd-(0\.|1\.[0-2][^0-9])", string:banner))
{
 security_hole(port);
 exit(0);
}

# digatech(sunrise)-1.2(03)

if(egrep(pattern:".*digatech[^0-9]*-(0\.|1\.[01][^0-9]|1\.2.(0[0-2]))", string:banner))
{ 
 security_hole(port);
 exit(0);
}

# ????
if(egrep(pattern:".*methane.*0\.(0.*|(1\.[0-2]))[^0-9]", string:banner, icase:TRUE))
{
 security_hole(port);
 exit(0);
}

# 
