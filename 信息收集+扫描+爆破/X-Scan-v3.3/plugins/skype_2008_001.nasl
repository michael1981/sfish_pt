#
# (C) Tenable Network Security
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
  script_id(30206);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-0454", "CVE-2008-0582", "CVE-2008-0583");
  script_bugtraq_id(27338);
  script_xref(name:"OSVDB", value:"42863");
  script_xref(name:"OSVDB", value:"42864");
  script_xref(name:"OSVDB", value:"42865");
  script_xref(name:"OSVDB", value:"42868");

  script_name(english:"Skype Web Content Zone Multiple Field Remote Code Execution");
  script_summary(english:"Checks version of Skype");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Skype client is affected by a remote code execution issue
through the web handler." );
 script_set_attribute(attribute:"description", value:
"The version of Skype installed on the remote host reportedly may allow
a remote attacker to execute arbitrary code by enticing the user to
retrieve specially crafted we content through the skype interface." );
 script_set_attribute(attribute:"see_also", value:"http://www.skype.com/security/skype-sb-2008-001-update2.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.skype.com/security/skype-sb-2008-002.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.skype.com/security/skype-sb-2008-001-update1.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Skype release 3.6.0.248 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("skype_version.nbin", "smb_nativelanman.nasl");
  script_require_keys("Services/skype");
  script_require_ports(139, 445);

  exit(0);
}


# The flaw only affects Windows hosts.
os = get_kb_item("Host/OS/smb");
if (!os || "Windows" >!< os) exit(0);


port = get_kb_item("Services/skype");
if (!port) exit(0);
if (!get_port_state(port)) exit(0);


# nb: "ts = 802011429" => "version = 3.6.0.248"
ts = get_kb_item("Skype/" + port + "/stackTimeStamp");
if (ts && ts < 802011429) security_hole(port);
