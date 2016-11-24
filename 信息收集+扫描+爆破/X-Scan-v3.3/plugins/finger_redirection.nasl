#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10073);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0105", "CVE-1999-0106");
 script_xref(name:"OSVDB", value:"64");
 script_xref(name:"OSVDB", value:"5769");

 script_name(english:"Finger Recursive Request Arbitrary Site Redirection");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote host to perform third-party host scans." );
 script_set_attribute(attribute:"description", value:
"The remote finger service accepts to redirect requests.  That is,
users can perform requests like :

		finger user@host@victim

This allows an attacker to use this computer as a relay to gather
information on a third-party network. In addition, this type of 
syntax can be used to create a denial of service condition on the
remote host." );
 script_set_attribute(attribute:"solution", value:
"Disable the remote finger daemon (comment out the 'finger' line in
/etc/inetd.conf and restart the inetd process) or upgrade it to a more
secure one." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 
 script_summary(english:"Finger user@host1@host2");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"Finger abuses");
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
  # cisco
  data = recv(socket:soc, length:2048, timeout:5);
  if(data)exit(0);
  
  buf = string("root@", get_host_name(), "\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  data_low = tolower(data);
  
  if(data_low && !("such user" >< data_low) && 
     !("doesn't exist" >< data_low) && !("???" >< data_low)
     && !("welcome to" >< data_low) && !("forward" >< data_low)){
     		security_warning(port);
		set_kb_item(name:"finger/user@host1@host2", value:TRUE);
		}
  close(soc);
 }
}
