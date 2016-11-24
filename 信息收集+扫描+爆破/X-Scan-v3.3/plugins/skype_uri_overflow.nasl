#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
  script_id(29250);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-5989");
  script_bugtraq_id(26748);
  script_xref(name:"OSVDB", value:"39170");

  script_name(english:"Skype skype4com URI Handler Remote Heap Corruption");
  script_summary(english:"Checks version of Skype");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Skype client is affected by a buffer overflow vulnerability" );
 script_set_attribute(attribute:"description", value:
"The version of Skype installed on the remote host is vulnerable to a
heap overflow attack in the skype4com uri handler. 

To exploit this vulnerability, a remote attacker must trick a user on
the affected host into clicking on a specially-crafted Skype URL." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-070.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Skype release 3.6.0.216" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

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


# nb: "ts = 711112234" => "version = 3.6.0.216"
ts = get_kb_item("Skype/" + port + "/stackTimeStamp");
if (ts && ts < 711112234) security_hole(port);
