#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21322);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-1993");
  script_bugtraq_id(17671);
  script_xref(name:"OSVDB", value:"24967");

  script_name(english:"Firefox < 1.5.0.3 iframe.contentWindow.focus() Overflow");
  script_summary(english:"Checks Firefox version number");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host may be prone to a denial of service
attack." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox may allow a malicious site to crash
the browser and potentially to run malicious code when attempting to
use a deleted controller context. 

Successful exploitation requires that 'designMode' be turned on." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/431878/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-30.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.5.0.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (ver[0] == 1 && ver[1] == 5 && ver[2] == 0 && ver[3] < 3) 
  security_warning(get_kb_item("SMB/transport"));
