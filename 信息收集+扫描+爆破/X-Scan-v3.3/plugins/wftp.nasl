#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
	script_id(10305);
	script_version ("$Revision: 1.19 $");
	script_cve_id("CVE-1999-0200");
	script_xref(name:"OSVDB", value:"241");

	script_name(english:"WFTP Unpassworded Guest Account");
	script_summary(english:"Checks if any account can access the FTP server");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host is vulnerable to unauthorized access.'
  );

  script_set_attribute(
    attribute:'description',
    value:"This FTP server accepts any login/password combination. This is a real
threat, since anyone can browse the FTP section of your disk without your consent."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to a supported version of Windows or disable the FTP server."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://support.microsoft.com/default.aspx?scid=kb;EN-US;137853'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C'
  );

  script_end_attributes();

	script_category(ACT_GATHER_INFO);

	script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
	script_family(english:"FTP");
	script_dependencie("find_service1.nasl", "DDI_FTP_Any_User_Login.nasl",
	 "ftpserver_detect_type_nd_version.nasl");
	script_require_ports("Services/ftp", 21);
	exit(0);
}

#
# The script code starts here
#

include('ftp_func.inc');
port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (	get_kb_item('ftp/'+port+'/backdoor') ||
	get_kb_item('ftp/'+port+'/broken') ) exit(0);

if(get_port_state(port))
{
  if(get_kb_item("ftp/" + port + "/AnyUser"))exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:"bogusbogus", pass:"soogjksjka"))
  {
   security_hole(port);
  }
  close(soc);
 }
}
