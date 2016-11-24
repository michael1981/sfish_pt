#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34269);
  script_version("$Revision: 1.7 $");

  script_cve_id(
    "CVE-2008-0016",
    "CVE-2008-3835",
    "CVE-2008-3837",
    "CVE-2008-4058",
    "CVE-2008-4059",
    "CVE-2008-4060",
    "CVE-2008-4061",
    "CVE-2008-4062",
    "CVE-2008-4063",
    "CVE-2008-4064",
    "CVE-2008-4065",
    "CVE-2008-4066",
    "CVE-2008-4067",
    "CVE-2008-4068",
    "CVE-2008-4069",
    "CVE-2008-4070"
  );
  script_bugtraq_id(31346, 31397, 31411);
  script_xref(name:"OSVDB", value:"48772");
  script_xref(name:"OSVDB", value:"48773");
  script_xref(name:"OSVDB", value:"48780");
  script_xref(name:"Secunia", value:"32010");

  script_name(english:"SeaMonkey < 1.1.12");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey is affected by various security
issues :

  - Using a specially crafted UTF-8 URL in a hyperlink, an
    attacker might be able to exploit a stack buffer 
    overflow in the Mozilla URL parsing routes to execute
    arbitrary code. (MFSA 2008-37)

  - It is possible to bypass the same-origin check in 
    'nsXMLDocument::OnChannelRedirect()'. (MFSA 2008-38)

  - An attacker can cause the content window to move while
    the mouse is being clicked, causing an item to be 
    dragged rather than clicked-on. (MFSA 2008-40)

  - Privilege escalation is possible via 'XPCnativeWrapper'
    pollution. (MFSA 2008-41)

  - There are several stability bugs in the browser engine
    that may lead to crashes with evidence of memory 
    corruption. (MFSA 2008-42)

  - Certain BOM characters and low surrogate characters,
    if HTML-escaped, are stripped from JavaScript code
    before it is executed, which could allow for cross-
    site scripting attacks. (MFSA 2008-43)

  - The 'resource:' protocol allows directory traversal 
    on Linux when using URL-encoded slashes, and it can
    by used to bypass restrictions on local HTML files.
    (MFSA 2008-44)

  - A bug in the XBM decoder allows random small chunks of
    uninitialized memory to be read. (MFSA 2008-45)

  - There is a heap buffer overflow that can be triggered
    when canceling a newsgroup message. (MFSA 2008-46)" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-37.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-38.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-40.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-41.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-42.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-43.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-44.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-45.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-46.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.1.12 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}


include("misc_func.inc");


ver = read_version_in_kb("SeaMonkey/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 && 
    (
      ver[1] == 0 ||
      (ver[1] == 1 && ver[2] < 12)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
