#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35778);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0040", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773",
                "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776", "CVE-2009-0777");
  script_bugtraq_id(33990);
  script_xref(name:"OSVDB", value:"52444");
  script_xref(name:"OSVDB", value:"52445");
  script_xref(name:"OSVDB", value:"52446");
  script_xref(name:"OSVDB", value:"52447");
  script_xref(name:"OSVDB", value:"52448");
  script_xref(name:"OSVDB", value:"52449");
  script_xref(name:"OSVDB", value:"52450");
  script_xref(name:"OSVDB", value:"52451");
  script_xref(name:"OSVDB", value:"52452");

  script_name(english:"Firefox < 3.0.7 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 3.0.7. Such 
versions are potentially affected by the following security 
issues :

  - By exploiting stability bugs in the browser engine, it 
    might be possible for an attacker to execute arbitrary 
    code on the remote system under certain conditions. 
    (MFSA 2009-07)

  - A vulnerability in Mozilla's garbage collection process
    could be exploited to run arbitrary code on the remote
    system. (MFSA 2009-08)

  - It may be possible for a website to read arbitrary XML
    data from another domain by using nsIRDFService and a 
    cross-domain redirect. (MFSA 2009-09)

  - Vulnerabilities in the PNG libraries used by Mozilla
    could be exploited to execute arbitrary code on the 
    remote system. (MFSA 2009-10)

  - Certain invisible characters are decoded before being
    displayed on the location bar. An attacker may be able
    to exploit this flaw to spoof the location bar and 
    display a link to a malicious URL. (MFSA 2009-11)" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-07.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-08.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-09.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-10.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-11.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 3.0.7 or later." );
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
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 7)
) security_hole(get_kb_item("SMB/transport"));
