#
# (C) Tenable Network Security, Inc.
# 

# v1.2: 10/19/2004 KK Liu adjust to remove false-potive on XP hosts 


include("compat.inc");

if(description)
{
 script_id(15464);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-0840");
 script_bugtraq_id(11374);
 script_xref(name:"OSVDB", value:"10696");
 script_xref(name:"IAVA", value:"2004-b-0013");

 script_name(english:"Microsoft Windows/Exchange SMTP DNS Lookup Overflow (885881)");

 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft SMTP server which 
fails to validate DNS response data. An attacker can exploit this flaw
to execute arbitrary code subject to the priviliges of the SMTP
application server process." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/MS04-035.mspx" );
 script_set_attribute(attribute:"solution", value:
"Apply the bulletin referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks the remote SMTP daemon version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#


include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

banner = get_smtp_banner(port:port);
if ( ! banner ) exit(0);

if ( "Microsoft ESMTP MAIL Service, Version: " >< banner )
{
 version = egrep(string:banner, pattern:"Microsoft ESMTP MAIL Service, Version: ");
 version = ereg_replace(string:version, pattern:".*Microsoft ESMTP MAIL Service, Version: (.*) ready", replace:"\1");
 ver = split(version, sep:".", keep:0);
 # KK Liu
 #5.0.2195 - Windows 2000
 #6.0.2600 - Windows XP
 #6.0.3790 - Windows 2003
 #6.0.6249 - Exchange 2000 SP3
 #6.0.3790.0 - Exchange 2003
 if ( int(ver[0]) == 6 )
 {
  if (int(ver[2]) > 2600) # KK Liu - only Win2003, WinXP2003 & Win2K+Exg2003, XP not affected
  {
  	if ( int(ver[1]) == 0 && ( int(ver[2]) < 3790 || ( int(ver[2]) == 3790 && int(ver[3]) < 211 ) ) ) security_hole(port);
  }
 }
}
