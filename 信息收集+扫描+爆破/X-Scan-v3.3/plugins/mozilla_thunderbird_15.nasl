#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20735);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-0236");
  script_bugtraq_id(16271);
  script_xref(name:"OSVDB", value:"22510");

  script_name(english:"Mozilla Thunderbird < 1.5 Attachment Extension Spoofing");
  script_summary(english:"Checks for Mozilla Thunderbird < 1.5");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of Mozilla Thunderbird is affected by an attachment
spoofing vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Mozilla Thunderbird, an email client. 

The remote version of this software does not display attachments
correctly in emails.  Using an overly-long filename and
specially-crafted Content-Type headers, an attacker may be able to
leverage this issue to spoof the file extension and associated file
type icon and thereby trick a user into executing an arbitrary
program." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-22/advisory/" );
 script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=300246" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird 1.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Thunderbird/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] < 5)
) security_warning(get_kb_item("SMB/transport"));
