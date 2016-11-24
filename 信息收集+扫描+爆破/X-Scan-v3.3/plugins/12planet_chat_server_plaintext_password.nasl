#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11591);
 script_bugtraq_id(7354);
 script_xref(name:"OSVDB", value:"50429");
 # NOTE: no CVE id assigned (jfs, december 2003)

 script_version ("$Revision: 1.12 $");

 script_name(english:"12Planet Chat Server Administration Authentication ClearText Credential Disclosure");
 script_summary(english:"Checks for the data encapsulation of 12Planet Chat Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java Application that is affected by
a cleartext authentication vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running 12Planet Chat Server - a web based chat
server written in Java.

The connection to this server is done over clear text, which means that
an attacker who can sniff the data going to this host could obtain the
administrator password of the web site, and use it to gain unauthorized
access to this chat server." );
 script_set_attribute(attribute:"see_also", value:"http://www.cirt.dk/advisories/cirt-14-advisory.txt" );
 script_set_attribute(attribute:"solution", value:
"Add an HTTPS layer to the administration console for the deployment of
production servers." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:A/AC:H/Au:N/C:P/I:N/A:N" );
 script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 
 script_dependencies("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);
foreach port (ports)
{
 if(get_port_state(port))
 {
  res = http_get_cache(port:port, item:"/");
  if(res != NULL && "one2planet.tools.PSDynPage" >< res)
  {
    if(get_port_transport(port) == ENCAPS_IP){ security_note(port); exit(0); }
  }
 }
}
