# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-08.xml
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
 script_id(14564);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200408-08");
 script_cve_id("CVE-2004-1701", "CVE-2004-1702");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-08
(Cfengine: RSA Authentication Heap Corruption)


    Two vulnerabilities have been found in cfservd. One is a buffer
    overflow in the AuthenticationDialogue function and the other is a
    failure to check the proper return value of the ReceiveTransaction
    function.
  
Impact

    An attacker could use the buffer overflow to execute arbitrary code
    with the permissions of the user running cfservd, which is usually the
    root user. However, before such an attack could be mounted, the
    IP-based ACL would have to be bypassed. With the second vulnerability,
    an attacker could cause a denial of service attack.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Cfengine. (It should be
    noted that disabling cfservd will work around this particular problem.
    However, in many cases, doing so will cripple your Cfengine setup.
    Upgrading is strongly recommended.)
  
');
script_set_attribute(attribute:'solution', value: '
    All Cfengine users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-misc/cfengine-2.1.8"
    # emerge ">=net-misc/cfengine-2.1.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.coresecurity.com/common/showdoc.php?idx=387&idxseccion=10');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1701');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1702');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-08] Cfengine: RSA Authentication Heap Corruption');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cfengine: RSA Authentication Heap Corruption');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/cfengine", unaffected: make_list("ge 2.1.8", "lt 2.0.0"), vulnerable: make_list("le 2.1.7")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
