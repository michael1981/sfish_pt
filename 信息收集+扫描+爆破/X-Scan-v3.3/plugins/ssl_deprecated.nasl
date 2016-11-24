#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20007);
  script_version("$Revision: 1.9 $");

  script_name(english:"SSL Version 2 (v2) Protocol Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts traffic using a protocol with known
weaknesses." );
 script_set_attribute(attribute:"description", value:
"The remote service accepts connections encrypted using SSL 2.0, which
reportedly suffers from several cryptographic flaws and has been
deprecated for several years.  An attacker may be able to exploit
these issues to conduct man-in-the-middle attacks or decrypt
communications between the affected service and clients." );
 script_set_attribute(attribute:"see_also", value:"http://www.schneier.com/paper-ssl.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/187498" );
 script_set_attribute(attribute:"see_also", value:"http://www.linux4beginners.info/node/disable-sslv2" );
 script_set_attribute(attribute:"solution", value:
"Consult the application's documentation to disable SSL 2.0 and use SSL
3.0 or TLS 1.0 instead." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  script_summary(english:"Checks for use of a deprecated SSL protocol");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_keys("Transport/SSL");
  exit(0);
}


if (COMMAND_LINE) port = 443;
else port = get_kb_item("Transport/SSL");
if (!port || !get_port_state(port)) exit(0);


# There's a problem if we can connect using SSLv2.
soc = open_sock_tcp(port, transport:ENCAPS_SSLv2);
if (soc) {
  security_warning(port);
  close(soc);
}
