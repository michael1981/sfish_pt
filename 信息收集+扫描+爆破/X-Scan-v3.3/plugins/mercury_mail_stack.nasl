#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15867);
 script_version ("$Revision: 1.6 $");

 script_cve_id("CVE-2004-1211");
 script_bugtraq_id(11775, 11788);
 script_xref(name:"OSVDB", value:"12508");
 script_xref(name:"Secunia", value:"13348");
 script_xref(name:"milw0rm", value:"1375");
  
 script_name(english:"Mercury Mail Remote IMAP Server Remote Overflow");
 script_summary(english:"Checks for version of Mercury Mail");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote IMAP server has multiple buffer overflow vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running Mercury Mail server, an IMAP server for\n",
     "Windows.\n\n",
     "According to its banner, the version of Mercury Mail running on the\n",
     "remote host has multiple stack buffer overflow vulnerabilities.  A\n",
     "remote authenticated attacker could exploit these issues to crash\n",
     "the service or execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-12/0028.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-12/0099.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service2.nasl");	       		     
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");

 exit(0);
}

#
# The script code starts here
#

include("imap_func.inc");
port = get_kb_item("Services/imap");
if(!port) port = 143;

banner = get_imap_banner(port:port);
if ( ! banner ) exit(0);

if(egrep(pattern:"^\* OK.*IMAP4rev1 Mercury/32 v([0-3]\..*|4\.(00.*|01[^b-z].*))server ready.*", string:banner))
{
  security_hole(port);
}    
