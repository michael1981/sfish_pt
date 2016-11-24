#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(39372);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", 
                "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840",
                "CVE-2009-1841");
  script_bugtraq_id(35360, 35370, 35371, 35372, 35373, 35377, 35380, 35383, 35386, 35388, 35391);
  # BID 35326          -- it's been retired
  script_xref(name:"OSVDB", value:"55138");
  script_xref(name:"OSVDB", value:"55139");
  script_xref(name:"OSVDB", value:"55140");
  script_xref(name:"OSVDB", value:"55141");
  script_xref(name:"OSVDB", value:"55142");
  script_xref(name:"OSVDB", value:"55143");
  script_xref(name:"OSVDB", value:"55144");
  script_xref(name:"OSVDB", value:"55145");
  script_xref(name:"OSVDB", value:"55146");
  script_xref(name:"OSVDB", value:"55147");
  script_xref(name:"OSVDB", value:"55148");
  script_xref(name:"OSVDB", value:"55152");
  script_xref(name:"OSVDB", value:"55153");
  script_xref(name:"OSVDB", value:"55154");
  script_xref(name:"OSVDB", value:"55155");
  script_xref(name:"OSVDB", value:"55157");
  script_xref(name:"OSVDB", value:"55158");
  script_xref(name:"OSVDB", value:"55159");
  script_xref(name:"OSVDB", value:"55160");
  script_xref(name:"OSVDB", value:"55161");
  script_xref(name:"OSVDB", value:"55162");
  script_xref(name:"OSVDB", value:"55163");
  script_xref(name:"OSVDB", value:"55164");
  script_xref(name:"Secunia", value:"35331");

  script_name(english:"Firefox < 3.0.11 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 3.0.11. Such versions
are potentially affected by the following security issues :

  - Multiple memory corruption vulnerabilities could 
    potentially be exploited to execute arbitrary code. 
    (MFSA 2009-24)

  - Certain invalid Unicode characters, when used as a part
    of IDN, can be displayed as a whitespace in the location
    bar. An attacker can exploit this vulnerability to
    spoof the location bar. (MFSA 2009-25)  

  - It may be possible for local resources loaded via
    'file:' protocol to access any domain's cookies saved
    on a user's system. (MFSA 2009-26)

  - It may be possible to tamper with SSL data via non-200
    responses to proxy CONNECT requests. (MFSA 2009-27)

  - A race condition exists in 'NPObjWrapper_NewResolve' 
    when accessing the properties of a NPObject, a 
    wrapped JSObject. This flaw could be potentially
    exploited to execute arbitrary code on the remote
    system. (MFSA 2009-28)

  - If the owner document of an element becomes null after
    garbage collection, then it may be possible to execute
    the event listeners within the wrong JavaScript context.
    An attacker can potentially exploit this vulnerability
    to execute arbitrary JavaScript with chrome privileges.
    (MFSA 2009-29)  

  - When the 'file:' resource is loaded from the location
    bar, the resource inherits principal of the previously
    loaded document. This could potentially allow 
    unauthorized access to local files. (MFSA 2009-30)

  - While loading external scripts into XUL documents
    content-loading policies are not checked. 
    (MFSA 2009-31)   

  - It may be possible for scripts from page content to
    run with elevated privileges. (MFSA 2009-32)" 
);

 script_set_attribute(attribute:"see_also", value:"http://research.microsoft.com/apps/pubs/default.aspx?id=79323" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-24.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-25.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-26.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-27.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-28.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-29.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-30.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-31.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-32.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 3.0.11 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 11)
) security_hole(get_kb_item("SMB/transport"));
