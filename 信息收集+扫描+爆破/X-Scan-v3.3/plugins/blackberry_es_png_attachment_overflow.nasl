#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20982);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2344");
  script_bugtraq_id(16204);
  script_xref(name:"OSVDB", value:"22299");

  script_name(english:"BlackBerry Enterprise Server PNG Attachment Buffer Overflow");
  script_summary(english:"Checks version number of BlackBerry Enterprise Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of BlackBerry Enterprise Server installed on the remote
host reportedly is affected by a heap-based buffer overflow that can
be triggered by a malformed PNG attachment.  Exploitation of this
issue may cause the Attachment Service to stop responding or crash and
may even allow for the execute of arbitrary code subject to the
privileges under which the application runs, generally
'Administrator'." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c10eb5db" );
 script_set_attribute(attribute:"solution", value:
"Install the appropriate service pack / hotfix as described in the
vendor advisory referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("blackberry_es_installed.nasl");
  script_require_keys("BlackBerry_ES/Product", "BlackBerry_ES/Version");

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


prod = get_kb_item("BlackBerry_ES/Product");
ver = get_kb_item("BlackBerry_ES/Version");
if (prod && ver) {
  if (
    (
      "Domino" >< prod && 
      ver =~ "^([0-3]\..*|4\.0\.([0-2].*))"
    ) ||
    (
      "Exchange" >< prod && 
      ver =~ "^([0-3]\..*|4\.0\.([0-2].*|3 \(Bundle))"
    ) ||
    (
      "GroupWise" >< prod && 
      ver =~ "^([0-2]\..*|4\.0\.([0-2].*))"
    )
  ) {
    security_warning(kb_smb_transport());
  }
}
