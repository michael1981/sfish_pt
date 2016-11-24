#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(11311);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2002-0692");
 script_bugtraq_id(5804);
 
 script_name(english:"Microsoft FrontPage Extensions shtml.exe Remote Overflow");
 script_summary(english:"Checks for the presence of shtml.exe");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "An application running on the remote web server may be vulnerable\n",
     "to a buffer overflow attack."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host has FrontPage Server Extensions (FPSE) installed.\n\n",
     "There is a denial of service / buffer overflow condition in the\n",
     "program 'shtml.exe' which comes with it. However, no public detail\n",
     "has been given regarding this issue yet, so it's not possible to\n",
     "remotely determine if you are vulnerable to this flaw or not.\n\n",
     "If you are, an attacker may use it to crash your web server\n",
     "(FPSE 2000) or execute arbitrary code (FPSE 2002). Please see the\n",
     "Microsoft Security Bulletin MS02-053 to determine if you are\n",
     "vulnerable or not."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.microsoft.com/technet/security/bulletin/ms02-053.mspx"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Refer to the Microsoft Security Bulletin."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"Web Servers");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie(
   "http_version.nasl", "www_fingerprinting_hmap.nasl",
   "smb_registry_full_access.nasl", "smb_reg_service_pack_W2K.nasl",
   "smb_reg_service_pack_XP.nasl", "frontpage_chunked_overflow.nasl"
 );
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
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

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

w = http_send_recv3(method:"GET", item:"/_vti_bin/shtml.exe", port:port);
if (isnull(w)) exit(1, "The web server did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);

  if("Smart HTML" >< res){
  w = http_send_recv3(method:"GET", item:"/_vti_bin/shtml.exe/nessus.htm", port:port);
  if (isnull(w)) exit(1, "The web server did not answer");
  res = strcat(w[0], w[1], '\r\n', w[2]);
  if ("&quot;nessus.htm&quot;" >!< res ) security_hole ( port ) ;
 }


