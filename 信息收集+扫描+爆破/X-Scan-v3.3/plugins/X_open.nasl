#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(19948);
  script_version ("$Revision: 1.8 $");
  script_cve_id("CVE-1999-0526");
  script_xref(name:"OSVDB", value:"309");

  script_name(english:"X11 Server Unauthenticated Access");
 script_set_attribute(attribute:"synopsis", value:
"The remote X11 server accepts connections from anywhere." );
 script_set_attribute(attribute:"description", value:
"The remote X11 server accepts connection from anywhere. An attacker
may connect to it to eavesdrop on the keyboard and mouse events of
a user on the remote host. It is even possible for an attacker to 
grab a screenshot of the remote host or to display arbitrary programs.

An attacker may exploit this flaw to obtain the username and password
of a user on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Restrict access to this port by using the 'xhost' command. 
If the X11 client/server facility is not used, disable TCP entirely." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"X11 determines if X11 is open");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 script_dependencie("X.nasl");
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_require_ports(6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009);
 exit(0);
}



for ( i = 0 ; i < 10 ; i ++ )
{
 if ( get_kb_item("x11/" + int(i + 6000) + "/open") ) security_warning(i + 6000);
}
