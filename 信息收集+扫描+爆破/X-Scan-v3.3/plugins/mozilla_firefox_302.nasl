#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34267);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061",
                "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4066",
                "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-5014");
  script_bugtraq_id(31346, 32281);
  script_xref(name:"OSVDB", value:"48746");
  script_xref(name:"OSVDB", value:"48747");
  script_xref(name:"OSVDB", value:"48748");
  script_xref(name:"OSVDB", value:"48749");
  script_xref(name:"OSVDB", value:"48750");
  script_xref(name:"OSVDB", value:"48751");
  script_xref(name:"OSVDB", value:"48759");
  script_xref(name:"OSVDB", value:"48760");
  script_xref(name:"OSVDB", value:"48761");
  script_xref(name:"OSVDB", value:"48762");
  script_xref(name:"OSVDB", value:"48763");
  script_xref(name:"OSVDB", value:"48764");
  script_xref(name:"OSVDB", value:"48765");
  script_xref(name:"OSVDB", value:"48766");
  script_xref(name:"OSVDB", value:"48767");
  script_xref(name:"OSVDB", value:"48768");
  script_xref(name:"OSVDB", value:"48769");
  script_xref(name:"OSVDB", value:"48770");
  script_xref(name:"OSVDB", value:"48771");
  script_xref(name:"OSVDB", value:"50141");
  script_xref(name:"Secunia", value:"32011");

  script_name(english:"Firefox < 3.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox 3.0 is earlier than 3.0.2.  Such
versions are potentially affected by the following security issues :

  - An attacker can cause the content window to move while
    the mouse is being clicked, causing an item to be 
    dragged rather than clicked-on (MFSA 2008-40).

  - Privilege escalation is possible via 'XPCnativeWrapper'
    pollution (MFSA 2008-41).

  - There are several stability bugs in the browser engine
    that may lead to crashes with evidence of memory 
    corruption (MFSA 2008-42).

  - Certain BOM characters and low surrogate characters,
    if HTML-escaped, are stripped from JavaScript code
    before it is executed, which could allow for cross-
    site scripting attacks (MFSA 2008-43).

  - The 'resource:' protocol allows directory traversal 
    on Linux when using URL-encoded slashes, and it can
    by used to bypass restrictions on local HTML files
    (MFSA 2008-44).

  - By tampering with the window.__proto__.__proto__ object, 
    one can cause the browser to place a lock on a non-
    native object, leading to a crash and possible code
    execution. (MFSA 2008-50)" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-40.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-41.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-42.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-43.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-44.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-50.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 3.0.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (ver[0] == 3 && ver[1] == 0 && ver[2] < 2) 
  security_hole(get_kb_item("SMB/transport"));
