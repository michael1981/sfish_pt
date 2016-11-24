#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11332);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2001-0935");
 script_xref(name:"OSVDB", value:"13998");
 script_xref(name:"IAVA", value:"2003-A-0009");
 
 script_name(english:"WU-FTPD Unspecified Security Issue");
 script_summary(english:"Checks the remote FTPd version");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote FTP server has an unspecified remote vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of WU-FTPD running on the remote host has an unspecified\n",
     "remote vulnerability. This is reportedly due to an unspecified bug in\n",
     "glob.c discovered by the SuSE security team.\n\n",
     "Nessus verified this vulnerability by looking at the banner\n",
     "of the remote FTP server."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to WU-FTPD version 2.6.1 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();
     
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
		  
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login", "ftp/wuftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;


banner = get_ftp_banner(port: port);
if(banner)
{
 if(egrep(pattern:".*wu-(1\..*|2\.[0-5]\.|2\.6\.0).*", string:banner))security_hole(port);
}
