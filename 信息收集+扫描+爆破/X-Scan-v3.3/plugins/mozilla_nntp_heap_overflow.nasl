#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16085);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2004-1316");
 script_bugtraq_id(12131, 12407);
 script_xref(name:"OSVDB", value:"12637");

 script_name(english:"Mozilla nsNNTPProtocol.cpp NNTP news:// URI Handling Overflow DoS");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to a heap overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote version of Mozilla is vulnerable to a heap overflow attack
against its NNTP functionality. 

This may allow an attacker to execute arbitrary code on the remote
host. 

To exploit this flaw, an attacker would need to set up a rogue news
site and lure a victim on the remote host into reading news from it." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/mfsa2005-06.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla 1.7.5 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines the version of Mozilla");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Version");
 exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 7 ||
      (ver[1] == 7 && ver[2] < 5)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
