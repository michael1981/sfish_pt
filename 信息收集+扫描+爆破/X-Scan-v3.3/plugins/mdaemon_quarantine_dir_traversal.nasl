#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19310);
  script_version("$Revision: 1.6 $");

  script_bugtraq_id(14400);
  script_xref(name:"OSVDB", value:"18348");
  script_xref(name:"Secunia", value:"16173");

  script_name(english:"MDaemon Content Filter Traversal Arbitrary File Write");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is prone to directory traversal attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Alt-N MDaemon, an SMTP/IMAP server for
Windows. 

According to its banner, the version of MDaemon on the remote host is
prone to a directory traversal flaw that can be exploited to overwrite
files outside the application's quarantine directory provided
MDaemon's attachment quarantine feature is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://files.altn.com/MDaemon/Release/RelNotes_en.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MDaemon version 8.1.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_summary(english:"Checks for content filter directory traversal vulnerability in MDaemon");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service2.nasl");
  script_exclude_keys("imap/false_imap");
  script_require_ports("Services/imap", 143);
  exit(0);
}


include("imap_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);
if (get_kb_item("imap/false_imap")) exit(0);


# Check the version number in the banner.
banner = get_imap_banner(port:port);
if (
  banner && 
  egrep(string:banner, pattern:"^\* OK .*IMAP4rev1 MDaemon ([0-7]\..+|8\.0\..+) ready")
) {
  security_hole(port);
  exit(0);
}
