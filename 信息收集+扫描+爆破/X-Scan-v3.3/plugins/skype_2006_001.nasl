#
# (C) Tenable Network Security
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
  script_id(21576);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-2312");
  script_bugtraq_id(18038);
  script_xref(name:"OSVDB", value:"25658");

  script_name(english:"Skype URI Handling Arbitrary File Download");
  script_summary(english:"Checks version of Skype");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Skype client is affected by an information disclosure
issue." );
 script_set_attribute(attribute:"description", value:
"The version of Skype installed on the remote host reportedly may allow
a remote attacker to initiate a file transfer to another Skype user by
means of a specially-crafted Skype URL." );
 script_set_attribute(attribute:"see_also", value:"http://www.skype.com/security/skype-sb-2006-001.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Skype release 2.0.*.105 / 2.5.*.79 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

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


# nb: "ts = 605101300" => "version = 2.0.0.105"
ts = get_kb_item("Skype/" + port + "/stackTimeStamp");
if (ts && ts < 605101300) security_note(port);
