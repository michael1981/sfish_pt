#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(21023);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-1206");
  script_bugtraq_id(17024);
  script_xref(name:"OSVDB", value:"23960");

  script_name(english:"Dropbear SSH Authorization-pending Connection Saturation DoS");
  script_summary(english:"Checks for authorization pending connection limit in Dropbear SSH server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is susceptible to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Dropbear, a small, open-source SSH server.

The version of Dropbear installed on the remote host by default has a limit of 
30 connections in the authorization-pending state; subsequent connections are 
closed immediately. This issue can be exploited trivially by an 
unauthenticated attacker to deny service to legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426999/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-March/042849.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Dropbear 0.48 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


port = get_kb_item("Services/ssh");
if (!port) port = 22;
if (!get_port_state(port)) exit(0);


# Make sure it's Dropbear.
banner = get_kb_item("SSH/banner/" + port);
if (!banner || "dropbear" >!< banner) exit(0);


if (safe_checks()) {
  if (ereg(pattern:"dropbear_0\.([0-3]|4[0-7])", string:banner))
    security_warning(port);
}
else {
  tries = 32;
  for (iter=0; iter<=tries; iter++) {
    soc = open_sock_tcp(port);
    if (!soc) break;

    res = recv(socket:soc, length:128);
    if (strlen(res)) {
      failed = 0;
    }
    else {
      failed++;
      if (failed > 1) {
        security_warning(port);
        exit(0);
      }
    }
  }
}
