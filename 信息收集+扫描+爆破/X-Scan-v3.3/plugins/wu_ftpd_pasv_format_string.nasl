#
# (C) Tenable Network Security, Inc.
#

# Affected: wu-ftpd up to 2.6.1


include("compat.inc");

if(description)
{
 script_id(11331);
 script_version ("$Revision: 1.12 $");

 script_cve_id("CVE-2001-0187");
 script_bugtraq_id(2296);
 script_xref(name:"OSVDB", value:"1744");
 
 script_name(english:"WU-FTPD Debug Mode Client Hostname Remote Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote WU-FTPd server, according to its version number, is
vulnerable to a format string attack when running in debug mode." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/639760" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?859aecba" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WU-FTPD version 2.6.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

		    
 script_summary(english:"Checks the remote ftpd version");
 script_category(ACT_GATHER_INFO); 
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
		  
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/wuftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#
include("global_settings.inc");
include("ftp_func.inc");
include("backport.inc");


# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (!get_tcp_port_state(port)) exit(0);

banner = get_backport_banner(banner:get_ftp_banner(port: port));
if (banner)
{
  banner = tolower(banner);
  if(egrep(pattern:"wu-((1\..*)|2\.([0-5]\..*|6\.[0-1]))", string:banner))
  	security_hole(port);
}
