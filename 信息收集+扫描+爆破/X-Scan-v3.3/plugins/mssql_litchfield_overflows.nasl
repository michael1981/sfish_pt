#
# (C) Tenable Network Security, Inc.
#

#
# ping code taken from mssql_ping by H D Moore
#
#
# MS02-061 supercedes MS02-020, MS02-038, MS02-039, MS02-043 and MS02-056
#
# BID xref by Erik Anderson <eanders@carmichaelsecurity.com>
# 
# Other CVEs: CVE-2002-0729, CVE-2002-0650
#

include("compat.inc");

if(description)
{
 script_id(11214);
 script_version ("$Revision: 1.33 $");

 script_cve_id("CVE-2002-1137", "CVE-2002-1138", "CVE-2002-0649", "CVE-2002-0650",
               "CVE-2002-1145", "CVE-2002-0644", "CVE-2002-0645", "CVE-2002-0721");
 script_bugtraq_id(5309, 5310, 5311, 5312, 5481, 5483, 5877, 5980);
 script_xref(name:"OSVDB", value:"878");
 script_xref(name:"OSVDB", value:"4577");
 script_xref(name:"OSVDB", value:"4578");
 script_xref(name:"OSVDB", value:"4776");
 script_xref(name:"OSVDB", value:"4777");
 script_xref(name:"OSVDB", value:"4778");
 script_xref(name:"OSVDB", value:"4779");
 script_xref(name:"OSVDB", value:"10127");
 script_xref(name:"OSVDB", value:"10131");
 script_xref(name:"OSVDB", value:"10136");
 script_xref(name:"OSVDB", value:"10137");
 script_xref(name:"OSVDB", value:"10138");
 script_xref(name:"OSVDB", value:"10139");
 script_xref(name:"OSVDB", value:"10140");
 script_xref(name:"IAVA", value:"2003-A-0001");
 script_xref(name:"IAVA", value:"2002-B-0004");

 script_name(english:"MS02-061: Microsoft SQL Server Multiple Vulnerabilities (uncredentialed check)");
 script_summary(english:"Microsoft's SQL UDP Info Query");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote database server is affected by multiple buffer overflows."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote MS SQL server is affected by several overflows that could\n",
   "be exploited by an attacker to gain SYSTEM access on that host.\n",
   "\n",
   "Note that a worm (sapphire) is exploiting these vulnerabilities in the\n",
   "wild."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:"http://www.microsoft.com/technet/security/bulletin/ms02-061.mspx"
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_dependencies("mssql_ping.nasl");
 script_require_keys("MSSQL/UDP/Ping");
 exit(0);
}

#
# The script code starts here
#


function sql_ping()
{
 local_var r, req, soc;

 req = raw_string(0x02);
 if(!get_udp_port_state(1434))exit(0);
 soc = open_sock_udp(1434);


 if(soc)
 {
	send(socket:soc, data:req);
	r  = recv(socket:soc, length:4096);
	close(soc);
	return(r);
 }
}



r = sql_ping();
if(strlen(r) > 0)
 {
  soc = open_sock_udp(1434);
  send(socket:soc, data:raw_string(0x0A));
  r = recv(socket:soc, length:1);
  if(strlen(r) > 0 && ord(r[0]) == 0x0A)security_hole(port:1434, proto:"udp");
 }
exit(0);



