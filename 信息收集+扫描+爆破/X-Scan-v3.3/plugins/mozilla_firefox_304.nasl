#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34767);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-0017", "CVE-2008-4582", "CVE-2008-5015", "CVE-2008-5016", "CVE-2008-5017",
                "CVE-2008-5018", "CVE-2008-5019", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023",
                "CVE-2008-5024");
  script_bugtraq_id(31747, 32281);
  script_xref(name:"OSVDB", value:"49073");
  script_xref(name:"OSVDB", value:"49925");
  script_xref(name:"OSVDB", value:"49995");
  script_xref(name:"OSVDB", value:"50142");
  script_xref(name:"OSVDB", value:"50176");
  script_xref(name:"OSVDB", value:"50177");
  script_xref(name:"OSVDB", value:"50178");
  script_xref(name:"OSVDB", value:"50179");
  script_xref(name:"OSVDB", value:"50181");
  script_xref(name:"OSVDB", value:"50182");
  script_xref(name:"OSVDB", value:"50210");
  script_xref(name:"Secunia", value:"32713");

  script_name(english:"Firefox < 3.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox 3.0 is earlier than 3.0.4.  Such
versions are potentially affected by the following security issues :

  - Locally saved '.url' shortcut files can be used to read
    information stored in the local cache. (MFSA 2008-47)

  - 'file:' URIs are given chrome privileges when opened in
    the same tab as a chrome page or privileged 'about:' 
    page, which could allow an attacker to run arbitrary 
    JavaScript with chrome privileges. (MFSA 2008-51)

  - There are several stability bugs in the browser engine
    that may lead to crashes with evidence of memory 
    corruption. (MFSA 2008-52)

  - The browser's session restore feature can be used to 
    violate the same-origin policy and run JavaScript in 
    the context of another site. (MFSA 2008-53)

  - There is a buffer overflow that can be triggered by 
    sending a specially crafted 200 header line in the HTTP
    index response. (MFSA 2008-54)

  - Crashes and remote code execution in nsFrameManager are
    possible by modifying certain properties of a file 
    input element before it has finished initializing.
    (MFSA 2008-55)

  - The same-origin check in 
    'nsXMLHttpRequest::NotifyEventListeners()' can be 
    bypassed. (MFSA 2008-56)

  - The '-moz-binding' CSS property can be used to bypass
    security checks which validate codebase principals.
    (MFSA 2008-57)

  - There is an error in the method used to parse the 
    default namespace in an E4X document caused by quote 
    characters in the namespace not being properly escaped.
    (MFSA 2008-58)" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-47.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-51.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-52.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-53.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-54.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-55.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-56.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-57.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-58.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 3.0.4 or later." );
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

if (ver[0] == 3 && ver[1] == 0 && ver[2] < 4) 
  security_hole(get_kb_item("SMB/transport"));
