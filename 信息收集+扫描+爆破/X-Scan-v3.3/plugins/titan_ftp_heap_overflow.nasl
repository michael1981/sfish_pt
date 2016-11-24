#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(14591);
 script_cve_id("CVE-2004-1641");
 script_bugtraq_id(11069);
 script_xref(name:"OSVDB", value:"9397");
 script_version ("$Revision: 1.8 $");

 script_name(english:"Titan FTP Server Multiple Command Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote is running Titan FTP Server. All versions up to 
and including 3.21 are reported vulnerable to a remote heap 
overflow in the CWD, STAT or LIST command processing.

An attacker may deny service to legitimate users or execute 
arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Titan FTP 3.22 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Check Titan FTP server version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);

if (egrep(pattern:"^220.*Titan FTP Server ([0-2]\.|3\.([0-9][^0-9]|[0-1][0-9]|2[0-1])[^0-9])", string:banner) ) 
	security_hole(port);
