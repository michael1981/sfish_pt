#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15465);
 script_version ("$Revision: 1.12 $");

 script_cve_id("CVE-2004-0574");
 script_bugtraq_id(11379);
 script_xref(name:"OSVDB", value:"10697");
 script_xref(name:"IAVA", value:"2004-A-0018");

 script_name(english:"MS04-036: Microsoft NNTP Component Remote Overflow (883935) (uncredentialed check)");
 script_summary(english:"Checks the remote NNTP daemon version");

 script_set_attribute(
  attribute:"synopsis",
  value:"The remote NNTP server is susceptible to a buffer overflow attack."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running a version of Microsoft NNTP server that is\n",
   "vulnerable to a buffer overflow issue.\n",
   "\n",
   "An attacker may exploit this flaw to execute arbitrary commands on the\n",
   "remote host with the privileges of the NNTP server process."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:"http://www.microsoft.com/technet/security/bulletin/MS04-036.mspx"
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencie("nntpserver_detect.nasl");
 script_require_ports("Services/nntp", 119);
 exit(0);
}

#
# The script code starts here
#



port = get_kb_item("Services/nntp");
if(!port)port = 119;
if (! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
banner = recv_line(socket:soc, length:8192);
if ( ! banner ) exit(0);
close(soc);

if ( "200 NNTP Service" >< banner )
{
 version = egrep(string:banner, pattern:"^200 NNTP Service");
 version = ereg_replace(string:version, pattern:"^200 NNTP Service .* Version: (.*) ", replace:"\1");
 ver = split(version, sep:".", keep:0);
 if ( int(ver[0]) == 6 )
 {
  if ( int(ver[1]) == 0 && ( int(ver[2]) < 3790 || ( int(ver[2]) == 3790 && int(ver[3]) < 206 ) ) ) security_hole(port);
 }

 if ( int(ver[0]) == 5 )
 {
  if ( int(ver[1]) == 0 && ( int(ver[2]) < 2195 || ( int(ver[2]) == 2195 && int(ver[3]) < 6972 ) ) ) security_hole(port);
 }
}
