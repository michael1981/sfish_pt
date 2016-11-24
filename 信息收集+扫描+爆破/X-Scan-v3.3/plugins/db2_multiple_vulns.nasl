#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 2191 ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15486);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2004-1372","CVE-2005-0417","CVE-2005-4863","CVE-2005-4864","CVE-2005-4865","CVE-2005-4866","CVE-2005-4867",
   "CVE-2005-4868","CVE-2005-4869","CVE-2005-4870","CVE-2005-4871");
 script_bugtraq_id(11405, 11404, 11403, 11402, 11401, 11400, 11399, 11398, 
   11397, 11396, 11390, 12170, 11327, 11089, 12508, 12509, 12510, 12511, 
   12512, 12514);
 script_xref(name:"OSVDB", value:"14661");
 script_xref(name:"OSVDB", value:"12759");
 script_xref(name:"OSVDB", value:"12758");
 script_xref(name:"OSVDB", value:"12757");
 script_xref(name:"OSVDB", value:"12756");
 script_xref(name:"OSVDB", value:"12755");
 script_xref(name:"OSVDB", value:"12754");
 script_xref(name:"OSVDB", value:"10523");
 script_xref(name:"OSVDB", value:"10518");
 script_xref(name:"OSVDB", value:"10517");
 script_xref(name:"OSVDB", value:"10515");
 script_xref(name:"OSVDB", value:"10514");
 script_xref(name:"OSVDB", value:"9526");
 script_xref(name:"OSVDB", value:"9525");
 script_xref(name:"Secunia", value:"12436");
 script_xref(name:"Secunia", value:"12733");
 script_xref(name:"Secunia", value:"12733");

 script_name(english:"DB2 < 8 Fix Pack 7a Multiple Vulnerabilities");
 script_summary(english:"IBM DB2 version check");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote database server has multiple vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
      "The remote host is running a vulnerable version of IBM DB2.\n\n",
      "There are multiple remote buffer overflow vulnerabilities in this\n",
      "version which may allow an attacker to cause a denial of service, or\n",
      "possibly execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.ngssoftware.com/advisories/db223122004K.txt"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/vulnwatch/2004-q3/0039.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-12/0356.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0022.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0025.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0026.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0027.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0028.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0029.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0031.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0032.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/ntbugtraq/2005-q1/0088.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to IBM DB2 V8 FixPak 7a or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"Databases");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencies("db2_das_detect.nasl");
 script_require_ports("Services/db2das", 523);
 exit(0);
}

#


port = get_kb_item("Services/db2das");
if (!port) port = 523;
if ( !get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
r = recv(socket:soc, length:4096);
if ( ! r ) exit(0);

sql = strstr(r, "SQL0");
if ( ! sql ) exit(0);
if ( ereg(pattern:"^SQL0([0-7][0-9]{3}|80[01][0-9])", string:sql) ) security_hole(port);
