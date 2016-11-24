
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2795
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27805);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2007-2795: seamonkey");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2795 (seamonkey)");
 script_set_attribute(attribute: "description", value: "SeaMonkey is an all-in-one Internet application suite. It includes
a browser, mail/news client, IRC client, JavaScript debugger, and
a tool to inspect the DOM for web pages. It is derived from the
application formerly known as Mozilla Application Suite.

-
Update Information:

SeaMonkey is an open source Web browser, advanced email and newsgroup client, I
RC chat client, and HTML editor.

By leveraging browser flaws, users could be fooled into possibly surrendering s
ensitive information (CVE-2007-1095, CVE-2007-3511, CVE-2007-3844, CVE-2007-533
4).

Malformed web content could result in the execution of arbitrary commands (CVE-
2007-5338, CVE-2007-5339, CVE-2007-5340).

Digest Authentication requests can be used to conduct a response splitting atta
ck (CVE-2007-2292).

The sftp protocol handler could be used to view the contents of arbitrary local
files (CVE-2007-5337).

Users of SeaMonkey are advised to upgrade to these erratum packages, which cont
ain patches that correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-3844", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");
script_summary(english: "Check for the version of the seamonkey package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"seamonkey-1.1.5-2.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
