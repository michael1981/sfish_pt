#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");

if (description)
{
  script_id(42148);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(36459);
  script_xref(name:"OSVDB", value:"58878");

  script_name(english:"Skype Extras Manager Vulnerability");
  script_summary(english:"Checks version of Skype");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Skype client is affected by a security vulnerability." );
  script_set_attribute(attribute:"description", value:
"The version of Skype installed on the remote host ships with a version
of the 'Skype Extras Manager' which is older than 2.0.0.67. 

The remote version of this package contains an unspecified security
vulnerability. 

Note this only affects Skype for Windows." );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57f8bbce" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Skype version 4.1.0.179 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/10/12"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/10/12"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/10/15"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("skype_version.nbin", "smb_nativelanman.nasl");
  script_require_keys("Services/skype");
  script_require_ports(139, 445);

  exit(0);
}


# The flaw only affects Windows hosts.
os = get_kb_item("Host/OS/smb");
if (!os) exit(1, "The 'Host/OS/smb' KB item is missing.");
if ("Windows" >!< os) exit(0, "The issue only affects Windows hosts.");


port = get_kb_item("Services/skype");
if (!port) exit(0);
if (!get_port_state(port)) exit(0);


# nb: "ts = 910091106" => "version = 4.1.0.179"
ts = get_kb_item("Skype/" + port + "/stackTimeStamp");
if (ts && ts < 910091106 ) security_warning(port);
