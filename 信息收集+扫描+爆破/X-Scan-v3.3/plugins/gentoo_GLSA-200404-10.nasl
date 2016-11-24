# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(14475);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200404-10");
 script_cve_id("CVE-2003-0856");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-10
(iproute local Denial of Service vulnerability)


    It has been reported that iproute can accept spoofed messages on the kernel
    netlink interface from local users. This could lead to a local Denial of
    Service condition.
  
Impact

    Local users could cause a Denial of Service.
  
Workaround

     A workaround is not currently known for this issue. All users are advised
     to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    All iproute users should upgrade to version 20010824-r5 or later:
    # emerge sync
    # emerge -pv ">=sys-apps/iproute-20010824-r5";
    # emerge ">=sys-apps/iproute-20010824-r5";
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2003-0856');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-10] iproute local Denial of Service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'iproute local Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-apps/iproute", unaffected: make_list("ge 20010824-r5"), vulnerable: make_list("le 20010824-r4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
