#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10522);
 script_version ("$Revision: 1.17 $");

 script_cve_id("CVE-2000-0917");
 script_bugtraq_id(1712);
 script_xref(name:"IAVA", value:"2001-t-0005");
 script_xref(name:"OSVDB", value:"421");

 script_name(english:"LPRng use_syslog() Remote Format String Arbitrary Command Execution");
 script_summary(english:"Checks for a vulnerable version of LPRng");

 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote print service is affected by format string\n",
   "vulnerabilities."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "LPRng seems to be running on this port. \n",
   "\n",
   "Versions of LPRng prior to 3.6.24 are missing format string arguments\n",
   "in at least two calls to 'syslog()' that handle user-supplied input.\n",
   "\n",
   "Using specially crafted input with format strings, an unauthenticated\n",
   "remote attacker may be able to leverage these issues to execute\n",
   "arbitrary code subject to the privileges under which the service\n",
   "operates, typically 'root'.\n",
   "\n",
   "Note that Nessus has not determined that the remote installation of\n",
   "LPRng is vulnerable, only that it is listening on this port."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2000-09/0293.html"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.kb.cert.org/vuls/id/382365"
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Upgrade if necssary to LPRng version 3.6.25."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2000/09/25"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2000/10/01"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl");
 script_require_ports(515);
 exit(0);
}


include("global_settings.inc");
if (report_paranoia < 2) exit(1, "Can't actually determine if the remote is vulnerable.");

if(get_port_state(515))
{
soc = open_sock_tcp(515);
if(soc)
{
 snd = raw_string(9)+ string("lp") + raw_string(0x0A);

 send(socket:soc, data:snd);
 r = recv(socket:soc, length:1024);
 if("SPOOLCONTROL" >< r)
 {
  security_hole(515);
 }
}
}
