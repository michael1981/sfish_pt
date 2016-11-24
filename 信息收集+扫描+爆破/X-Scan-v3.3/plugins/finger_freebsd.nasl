#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10534);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0915");
 script_bugtraq_id(1803);
 script_xref(name:"OSVDB", value:"433");

 script_name(english:"FreeBSD 4.1.1 Finger Arbitrary Remote File Access");
 script_summary(english:"Finger /path/to/file");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The finger service running on the remote host has an arbitrary\n",
     "file access vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The finger daemon running on the remote host will reveal the contents\n",
     "of arbitrary files when given a command similar to the following :\n\n",
     "  finger /etc/passwd@target\n\n",
     "Which will return the contents of /etc/passwd."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this finger daemon."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Finger abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("/etc/passwd\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  close(soc);
  if(egrep(pattern:".*root:.*:0:[01]:", string:data))
  	security_hole(port);
 }
}
