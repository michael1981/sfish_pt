#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10464);
 script_version ("$Revision: 1.17 $");

 script_cve_id("CVE-1999-0368");
 script_bugtraq_id(2242);
 script_xref(name:"OSVDB", value:"9163");
 
 script_name(english: "ProFTPD Multiple Remote Overflows (palmetto)");
             
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote ProFTPd server is running a 1.2.0preN version.

All the 1.2.0preN versions contain several security flaws that allow an
attacker to execute arbitrary code on this host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a fixed FTP server - http://www.proftpd.net" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
                 
script_end_attributes();

 
 script_summary(english:"Checks if the version of the remote proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
                  
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/proftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

banner = get_ftp_banner(port:port);

if(egrep(pattern:"^220 ProFTPD 1\.2\.0pre.*", string:banner))security_hole(port);

