#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12126);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2004-0385");
 script_bugtraq_id(9868);
 script_xref(name:"OSVDB", value:"4249");
 script_xref(name:"OSVDB", value:"15438");
 script_xref(name:"IAVA", value:"2004-t-0011");

 script_name(english:"Oracle Application Server Web Cache <= 9.0.4.0 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a heap
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Oracle Application 
Server Web Cache version 9.0.4.0 or older. The installed 
version is affected by a heap overflow vulnerability.
Provided Web Cache is running and configured to listen on
Oracle Application Server Web Cache listener port and 
accept requests from any client it may be possible for an
attacker to execute arbitrary code on the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://www.inaccessnetworks.com/ian/services/secadv01.txt" );
 script_set_attribute(attribute:"solution", value:
"http://otn.oracle.com/deploy/security/pdf/2004alert66.pdf" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Checks for version of Oracle AS WebCache");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_dependencie("http_version.nasl", "os_fingerprint.nasl");
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

banner = get_http_banner(port: port);
if(!banner)exit(0);

# Oracle AS10g/9.0.4 Oracle HTTP Server OracleAS-Web-Cache-10g/9.0.4.0.0 (N)

if(egrep(pattern:"^Server:.*OracleAS-Web-Cache-10g/(9\.0\.[0-3]\.[0-9]|2\..*)", string:banner))
{
   security_hole(port);
   exit(0);
}

if(egrep(pattern:"^Server:.*OracleAS-Web-Cache-10g/9\.0\.4\.0", string:banner))
{
  os = get_kb_item("Host/OS");
  if ( !os || ("Windows" >!< os && "Tru64" >!< os && "AIX" >!< os)) security_hole ( port );
}
