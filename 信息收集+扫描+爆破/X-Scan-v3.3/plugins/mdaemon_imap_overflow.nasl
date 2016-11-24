#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");


if(description)
{
 script_id(19252);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(14315, 14317);
 script_xref(name:"OSVDB", value:"18069");
 script_xref(name:"OSVDB", value:"18070");
 script_xref(name:"Secunia", value:"16097");
 
 script_name(english:"MDaemon IMAP Server Multiple AUTHENTICATE Commands Remote Overflow");
 script_summary(english:"Checks the remote version of MDaemon");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote IMAP server has multiple buffer overflow vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its banner, the remote version of MDaemon has multiple\n",
     "buffer overflow vulnerabilities.  A remote attacker could exploit\n",
     "these issues to crash the service, or possibly execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-07/0442.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to MDaemon 8.0.4 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

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
if(!port)port = 143;

banner = get_imap_banner ( port:port );
if ( ! banner ) exit(0);

if(egrep(pattern:"^\* OK .*IMAP4rev1 MDaemon ([0-7]\..*|8\.0\.[0-3]) ready", string:banner)) security_hole(port);
