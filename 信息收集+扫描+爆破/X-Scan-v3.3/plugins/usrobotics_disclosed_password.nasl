#
# (C) Tenable Network Security, Inc.
#

#
# Ref:
#  Date: Tue, 8 Jun 2004 13:41:11 +0200 (CEST)
#  From: Fernando Sanchez <fer@ceu.fi.udc.es>
#  To: bugtraq@securityfocus.com
#  Subject: U.S. Robotics Broadband Router 8003 admin password visible



include("compat.inc");

if(description)
{
 script_id(12272);
 script_version("$Revision: 1.7 $");
 script_bugtraq_id(10490);
 script_xref(name:"OSVDB", value:"53371");

 script_name(english:"US Robotics Broadband Router 8003 menu.htm Admin Password Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a US Robotics Broadband router. 

The device's administrator password is stored as plaintext in a
JavaScript function in the file '/menu.htm', which can be viewed by
anyone." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-06/0109.html" );
 script_set_attribute(attribute:"solution", value:
"Disable the webserver or filter the traffic to the webserver via an 
upstream firewall." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();


 script_summary(english:"US Robotics Password Check");

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


# start check

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);

r = http_send_recv3(item:"/menu.htm", port:port, method:"GET");
if (isnull(r)) exit(0);
res = r[2];

if (
  "function submitF" >< res &&
  "loginflag =" >< res &&
  "loginIP = " >< res &&
  "pwd = " >< res 
) {
  security_hole(port);
  set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
}

