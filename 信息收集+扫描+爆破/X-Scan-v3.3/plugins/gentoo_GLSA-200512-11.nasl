# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-11.xml
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
 script_id(20352);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200512-11");
 script_cve_id("CVE-2005-3694", "CVE-2005-3863");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200512-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200512-11
(CenterICQ: Multiple vulnerabilities)


    Gentoo developer Wernfried Haas discovered that when the "Enable
    peer-to-peer communications" option is enabled, CenterICQ opens a port
    that insufficiently validates whatever is sent to it. Furthermore,
    Zone-H Research reported a buffer overflow in the ktools library.
  
Impact

    A remote attacker could cause a crash of CenterICQ by sending
    packets to the peer-to-peer communications port, and potentially cause
    the execution of arbitrary code by enticing a CenterICQ user to edit
    overly long contact details.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All CenterICQ users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/centericq-4.21.0-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3694');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3863');
script_set_attribute(attribute: 'see_also', value: 'http://www.zone-h.org/en/advisories/read/id=8480/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200512-11] CenterICQ: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CenterICQ: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/centericq", unaffected: make_list("ge 4.21.0-r2"), vulnerable: make_list("lt 4.21.0-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
