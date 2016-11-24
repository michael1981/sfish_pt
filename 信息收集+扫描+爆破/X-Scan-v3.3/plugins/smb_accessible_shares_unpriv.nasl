#
# (C) Tenable Network Security, inc.
#


include("compat.inc");

if(description)
{
 script_id(42411);
 script_version ("$Revision: 1.1 $");

 script_cve_id("CVE-1999-0519", "CVE-1999-0520");
 script_bugtraq_id(8026);
 script_xref(name:"OSVDB", value:"299");

 script_name(english:"Microsoft Windows SMB Shares Unprivileged Access");
 script_summary(english:"Reports up to 100 remote accessible shares");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to access a network share." );
 script_set_attribute(attribute:"description", value:
"The remote has one or more Windows shares that can be accessed through
the network with the given credentials. 

Depending on the share rights, it may allow an attacker to read/write
confidential data." );
 script_set_attribute(attribute:"solution", value:
"To restrict access under Windows, open Explorer, do a right click on
each share, go to the 'sharing' tab, and click on 'permissions'." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/06");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 
 script_dependencies("smb_accessible_shares.nasl");
 script_require_keys("/tmp/10396/report", "/tmp/10396/port");
 exit(0);
}

rep = get_kb_item("/tmp/10396/report");
port = get_kb_item("/tmp/10396/port");
if (port && rep) security_hole(port: port, extra: rep);
