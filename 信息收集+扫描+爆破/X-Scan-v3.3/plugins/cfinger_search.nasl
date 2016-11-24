#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10038);
 script_cve_id("CVE-1999-0259");
 script_xref(name:"OSVDB", value:"32");
 
 script_version ("$Revision: 1.21 $");
 script_name(english:"cfingerd Wildcard Argument Information Disclosure");
 script_summary(english:"finger .@host feature");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote finger server has an information disclosure vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running 'cfingerd', a finger daemon.\n\n",
     "There is a bug in the remote cfinger daemon which allows a remote\n",
     "attacker to get the lists of the users of this system when issuing\n",
     "the command :\n\n",
     "  finger search.**@victim\n\n",
     "This information can be used by a remote attacker to mount further\n",
     "attacks."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1997_2/0328.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1997_2/0339.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "There is no known solution at this time.  Use another finger daemon,\n",
     "or disable this service in inetd.conf."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Finger abuses");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
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
  buf = string("search.**\r\n");

  send(socket:soc, data:buf);
  recv_line(socket:soc, length:2048);
  data = recv_line(socket:soc, length:2048);
  minus = "----";
  if(minus >< data)
  {
	for(i=1;i<11;i=i+1){
		data = recv_line(socket:soc, length:2048);
		if(!data)exit(0);
		}
	data = recv_line(socket:soc, length:2048);
	if(data){
  		data_low = tolower(data);
  		if(data_low && ("root" >< data_low)) 
		 {
     		 security_warning(port);
		 set_kb_item(name:"finger/search.**@host", value:TRUE);
		 }
		}
  }
  close(soc);
 }
}
