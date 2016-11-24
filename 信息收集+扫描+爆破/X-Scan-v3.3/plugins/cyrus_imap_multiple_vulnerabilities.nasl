#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17208);
 script_version ("$Revision: 1.9 $");
  
 script_cve_id("CVE-2005-0546");
 script_bugtraq_id(12636);
 script_xref(name:"OSVDB", value:"14089");
 script_xref(name:"OSVDB", value:"14090");
 script_xref(name:"OSVDB", value:"14091");
 script_xref(name:"OSVDB", value:"14092");
 script_xref(name:"OSVDB", value:"14093");

 script_name(english:"Cyrus IMAP Server < 2.2.11 Multiple Remote Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by multiple buffer overflow issues." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote Cyrus IMAP server is affected by
off-by-one errors in its imapd annotate extension and its cached
header handling which can be triggered by an authenticated user, a
buffer overflow in fetchnews that can be triggered by a peer news
admin, and an unspecified stack-based buffer overflow in imapd." );
 script_set_attribute(attribute:"see_also", value:"http://cyrusimap.web.cmu.edu/imapd/changes.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cyrus IMAP server version 2.2.11 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for the banner of Cyrus IMAPd");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("cyrus_imap_prelogin_overflow.nasl");
 script_require_ports("Services/imap", 143);

 exit(0);
}

#
# The script code starts here
#

include("imap_func.inc");
port = get_kb_item("Services/imap");
if(!port) port = 143;

banner = get_kb_item("imap/" + port + "/Cyrus");
if ( ! banner ) exit(0);
if(egrep(pattern:"^(1\..*|2\.0\..*|2\.1\.[1-9][^0-9]|2\.1\.1[01])[0-9]*$", string:banner))
    security_hole(port);
