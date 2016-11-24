#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11577);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2003-1470");
 script_bugtraq_id(7446);
 script_xref(name:"OSVDB", value:"55186");
 
 script_name(english:"MDaemon IMAP Server CREATE Command Mailbox Name Handling Overflow");
 script_summary(english:"Determines the version number of the remote IMAP server");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote IMAP server has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its banner, the version of MDaemon running on the remote\n",
     "host has a buffer overflow vulnerability in the CREATE command.  A\n",
     "remote attacker could exploit this to execute arbitrary code, or\n",
     "cause a denial of service.  A crash would prevent other MDaemon\n",
     "services (SMTP, POP) from running as well." 
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-04/0352.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to MDaemon 6.7.10 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#


include("imap_func.inc");
port = get_kb_item("Services/imap");
if(!port)port = 143;

banner  =  get_imap_banner ( port : port );
if ( ! banner )exit(0);
if(ereg(pattern:".* IMAP.* MDaemon ([0-5]\.|6\.([0-6]\.|7\.[0-9][^0-9]))", string:banner)) security_hole(port);
