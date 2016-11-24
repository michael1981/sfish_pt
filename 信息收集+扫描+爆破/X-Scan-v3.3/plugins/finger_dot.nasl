#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10072);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0198");
 script_xref(name:"OSVDB", value:"63");

 script_name(english:"Finger .@host Unused Account Disclosure");
 script_summary(english:"Finger .@host feature");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The finger service running on the remote host has an information\n",
     "disclosure vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "It is possible to force the remote finger daemon to display a list of\n",
     "accounts that have never been used by issuing the request :\n\n",
     "  finger .@target\n\n",
     "A remote attacker could use this information to guess which operating\n",
     "system is running, or to mount further attacks on these accounts."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?b5a66556"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Disable or filter access to the finger daemon."
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
  # Cisco
  data = recv(socket:soc, length:2048, timeout:5);
  if(data)exit(0);
  
  buf = string(".\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  close(soc);
  if(strlen(data)<100)exit(0);
  data_low = tolower(data);
  
  if(data_low && (!("such user" >< data_low)) && 
     (!("doesn't exist" >< data_low)) && (!("???" >< data_low))
     && (!("welcome to" >< data_low))){
     report = "
Nessus was able to obtain a list of the following accounts : 
" + data + "
";
     		security_warning(port:port, extra:report);
		set_kb_item(name:"finger/.@host", value:TRUE);
		}

 }
}
