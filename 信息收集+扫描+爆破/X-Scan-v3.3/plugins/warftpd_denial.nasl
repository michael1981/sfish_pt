#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(16270);
  script_cve_id("CVE-2005-0312");
  script_bugtraq_id(12384);
  script_xref(name:"OSVDB", value:"13225");
  script_version("$Revision: 1.5 $");

  script_name(english:"WarFTPd CWD Command Remote DoS");
  script_summary(english:"Checks the version of War FTP");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote FTP service is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running War FTP Daemon, an FTP server for Windows.

The remote version of this software is prone to a remote denial of
service vulnerability.  An attacker may exploit this flaw to crash the
remote service."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to War FTP Daemon 1.82-RC10."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=110687202332039&w=2'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_family(english:"FTP");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/ftp", 21);
  exit(0);
}


include("ftp_func.inc");

port = get_kb_item("Services/ftp");

if(!port)port = 21;

if(get_port_state(port))
{
 r = get_ftp_banner(port:port);
 if(!r)exit(0);

 if(egrep(pattern:"WarFTPd 1\.([0-9]\.|[0-7][0-9]\.|8[0-1]\.|82\.00-RC[0-9][^0-9]).*Ready",string:r))
 {
  security_warning(port);
 }
}
