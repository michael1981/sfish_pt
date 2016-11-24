#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15774);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-2416");
 script_bugtraq_id(11666);
 script_xref(name:"OSVDB", value:"11593");
 script_xref(name:"Secunia", value:"13085");

 script_name(english:"CCProxy Logging Compoent HTTP GET Request Remote Overflow");
 script_summary(english:"Does a version check");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote proxy has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of CCProxy running on the remote host has a buffer\n",
     "overflow vulnerabililty.  This issue is triggered by sending a long\n",
     "HTTP GET request.  A remote attacker could exploit this issue to\n",
     "crash the service, or potentially execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/secunia/2004-q4/0449.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.securiteam.com/exploits/6E0032KBPM.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to CCProxy version 6.3 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/ccproxy-smtp");
 exit(0);
}

#
# The script code starts here
#
include("smtp_func.inc");
port = get_kb_item("Services/ccproxy-smtp");
if ( ! port ) exit(0);
banner = get_smtp_banner ( port:port);
if ( egrep(pattern:"CCProxy ([0-5]\.|6\.[0-2]) SMTP Service Ready", string:banner) )
	security_hole ( port );

