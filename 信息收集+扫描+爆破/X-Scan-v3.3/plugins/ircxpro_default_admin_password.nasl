#
# (C) Tenable Network Security, Inc.
#

# 
#Ref: 
# From: "morning_wood" <se_cur_ity@hotmail.com>
# To: <bugtraq@securityfocus.com>
# Subject: IRCXpro 1.0 - Clear local and default remote admin passwords
# Date: Tue, 3 Jun 2003 00:57:45 -0700


include("compat.inc");

if(description)
{
 script_id(11697);
 script_version ("$Revision: 1.6 $");
 
 script_name(english:"IRCXPro Default Admin Password");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a management interface using a default
username/password combination." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running IRCXPro.

It is possible to connect to the management port of this
service (by default : 7100) by using the default login/password
combination admin/password.

An attacker may use this flaw to gain the control of this server." );
 script_set_attribute(attribute:"solution", value:
"Set a strong password for the admin user." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Logs into the remote administrative interface of ircxpro");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_require_ports("Services/ircxpro_admin", 7100);
 script_dependencies("find_service1.nasl");
 exit(0);
}

port = get_kb_item("Services/ircxpro_admin");
if(!port)port = 7100;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
r = recv_line(socket:soc, length:4096);
if('IRCXPRO' >!< r) exit(0);
r = recv_line(socket:soc, length:4096);
send(socket:soc, data:'ISIRCXPRO\r\n');
r = recv_line(socket:soc, length:4096);
if('IRCXPRO' >!< r) exit(0);
send(socket:soc, data:'AUTH admin password\r\n');
r = recv_line(socket:soc, length:4096);
if("WELCOME" >< r) security_warning(port);
