#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");

if (description)
{
  script_id(33125);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-1805", "CVE-2008-2545");
  script_bugtraq_id(29553);
  script_xref(name:"Secunia", value:"30547");
  script_xref(name:"OSVDB", value:"46010");

  script_name(english:"Skype file: URI Handling Security Bypass Arbitrary Code Execution");
  script_summary(english:"Checks version of Skype");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Skype client is affected by a security policy bypass
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Skype installed on the remote host reportedly uses
improper logic in its 'file:' URI handler when validating URLs by
failing to check for certain dangerous file extensions and checking
for others in a case-sensitive manner. 

If an attacker can trick a user on the affected host into clicking on
a specially-crafted 'file:' URI, he may be able to leverage this issue
to execute arbitrary code on the affected system subject to the user's
privileges. 

Note this only affects Skype for Windows." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=711" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/493081/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.skype.com/security/skype-sb-2008-003.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Skype version 3.8.0.139 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

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


# nb: "ts = 805281541" => "version = 3.8.0.139"
ts = get_kb_item("Skype/" + port + "/stackTimeStamp");
if (ts && ts < 805281541) security_hole(port);
