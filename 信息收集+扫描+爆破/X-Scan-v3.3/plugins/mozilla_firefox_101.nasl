#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3004) exit(1);

include("compat.inc");

if(description)
{
 script_id(17218);
 script_version("$Revision: 1.17 $");

 script_cve_id(
  "CVE-2004-1200",
  "CVE-2005-0230",
  "CVE-2005-0233",
  "CVE-2005-0255",
  "CVE-2005-0578",
  "CVE-2005-0584",
  "CVE-2005-0586",
  "CVE-2005-0587",
  "CVE-2005-0588",
  "CVE-2005-0589",
  "CVE-2005-0590",
  "CVE-2005-0591",
  "CVE-2005-0592",
  "CVE-2005-0593"
 );
 script_bugtraq_id(12533, 12461, 12470, 12468, 12466, 12465, 12234,
                   12153, 11854, 11823, 11752, 12655, 12659, 12728);
 script_xref(name:"OSVDB", value:"11151");
 script_xref(name:"OSVDB", value:"12868");
 script_xref(name:"OSVDB", value:"13578");
 script_xref(name:"OSVDB", value:"13610");
 script_xref(name:"OSVDB", value:"14185");
 script_xref(name:"OSVDB", value:"14187");
 script_xref(name:"OSVDB", value:"14188");
 script_xref(name:"OSVDB", value:"14189");
 script_xref(name:"OSVDB", value:"14190");
 script_xref(name:"OSVDB", value:"14191");
 script_xref(name:"OSVDB", value:"14192");
 script_xref(name:"OSVDB", value:"14193");
 script_xref(name:"OSVDB", value:"14194");
 script_xref(name:"OSVDB", value:"14195");
 script_xref(name:"OSVDB", value:"14196");
 script_xref(name:"OSVDB", value:"14198");

 script_name(english:"Firefox < 1.0.1 Multiple Vulnerabilities");
 script_summary(english:"Determines the version of Firefox");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote Windows host contains a web browser that is affected by\n",
     "multiple vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The installed version of Firefox is earlier than 1.0.1.  Such\n",
     "versions have multiple security issues, including vulnerabilities\n",
     "which may allow an attacker to impersonate a website by using an\n",
     "International Domain Name, or vulnerabilties that may allow\n",
     "arbitrary code execution."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/known-vulnerabilities/firefox10.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Firefox 1.0.1 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Firefox/Version");
 exit(0);
}

#

include("misc_func.inc");


ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] == 0 && ver[2] < 1)
) security_hole(get_kb_item("SMB/transport"));
