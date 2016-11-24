#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19696);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-2602", "CVE-2005-3089");
  script_bugtraq_id(14526, 14924);
  script_xref(name:"OSVDB", value:"18691");
  script_xref(name:"OSVDB", value:"19615");

  script_name(english:"Netscape Browser < 8.0.4 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws, including
arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Netscape Browser / Netscape Navigator, an
alternative web browser. 

The version of Netscape Browser / Netscape Navigator installed on the
remote host is prone to multiple flaws, including one that may allow
an attacker to execute arbitrary code on the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://security-protocols.com/advisory/sp-x17-advisory.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/mfsa2005-58.html" );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/16944/" );
 script_set_attribute(attribute:"solution", value:
"The Netscape Browser/Navigator has been discontinued.  While these
issues were reportedly fixed in 8.0.4, it is strongly recommended that
you consider upgrading to the latest version of a Mozilla Browser." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

  script_summary(english:"Checks for Netscape Browser <= 8.0.3.3");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("netscape_browser_detect.nasl");
  script_require_keys("SMB/Netscape/installed");
  exit(0);
}

#

include("global_settings.inc");


list = get_kb_list("SMB/Netscape/*");
if (isnull(list)) exit(0);

foreach key (keys(list))
{
  ver = key - "SMB/Netscape/";
  if (
    ver && 
    (
      ver =~ "^8\.0\.[0-3]([^0-9]|$)" ||
      (report_paranoia > 1 && ver =~ "^[0-7]\.")
    )
  )
  {
    security_hole(get_kb_item("SMB/transport"));
    exit(0);
  }
}
