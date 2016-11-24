#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(18367);
 script_version ("$Revision: 1.13 $");

 script_name(english: "Kibuv Worm Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host may be compromised." );
 script_set_attribute(attribute:"description", value:
"The welcome message on this port matches the banner of a known
backdoor.  This is highly suspicious.  The host is probably infected
by a backdoor and is probably under the control of malicious
attackers." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19420d0e" );
 script_set_attribute(attribute:"solution", value:
"Patch the affected system and run an antivirus." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();


 script_summary(english: "Detect some backdoors FTP banner (KIBUV, Agobot...)");
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_dependencie("find_service1.nasl");
 # Trend says that KIBUV.B is on 7955 but I saw it on 14920 and 42260
 script_require_ports("Services/three_digits", 7955);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");

banners = make_array(
"220 StnyFtpd 0wns j0",		"KIBUV.B",
"220 fuckFtpd 0wns j0",		"KIBUV.B" , 
"220 NzmxFtpd 0wns j0",		"KIBUV" , 
"220 Reptile welcomes you",	"Reptile",  
"220 Bot Server (Win32)",	"Agobot",
"220 *Ftpd 0wns j0",		"KIBUV unknown variant" );

function test(port)
{
 local_var b, ban, report, trojan;
 global_var desc, port;

 if (! get_port_state(port)) return 0;

 b = get_unknown_banner(port: port);
 # KIBUV.B is already processed by ftp_kibuv_worm.nasl and agobot 
 # by find_service2 and others...
 if (! b) return 0;

 foreach ban (keys(banners))
 {
  if (match(string: b, pattern: ban+'*'))
  {
   trojan=banners[ban];
   set_kb_item(name: 'ftp/'+port+'/backdoor', value: trojan);
   set_kb_item(name: 'backdoor/TCP/'+port, value: TRUE);
   set_kb_item(name: 'ftp/backdoor', value: trojan);

   report = string(
     "Backdoor : ", trojan, "\n",
     "Banner   : ", b, "\n"
   );
   security_hole(port:port, extra:report);
   return 1;
  }
 }
 return 0;
}

 # Trend says that KIBUV.B is on 7955 but I saw it on 14920 and 42260
ports = make_service_list(7955, 'Services/three_digits', 'Services/agobot.fo', 'Services/ftp');

foreach port (ports) test(port: port);
