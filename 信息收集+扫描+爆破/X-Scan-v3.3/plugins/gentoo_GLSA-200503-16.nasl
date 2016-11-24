# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-16.xml
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
 script_id(17318);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200503-16");
 script_cve_id("CVE-2005-0699", "CVE-2005-0704", "CVE-2005-0705", "CVE-2005-0739", "CVE-2005-0765", "CVE-2005-0766");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-16
(Ethereal: Multiple vulnerabilities)


    There are multiple vulnerabilities in versions of Ethereal earlier than
    0.10.10, including:
    The Etheric, 3GPP2 A11 and IAPP dissectors are vulnerable to buffer
    overflows (CAN-2005-0704, CAN-2005-0699 and CAN-2005-0739).
    The GPRS-LLC could crash when the "ignore cipher bit" option is
    enabled (CAN-2005-0705).
    Various vulnerabilities in JXTA and sFlow dissectors.
  
Impact

    An attacker might be able to use these vulnerabilities to crash
    Ethereal and execute arbitrary code with the permissions of the user
    running Ethereal, which could be the root user.
  
Workaround

    For a temporary workaround you can disable all affected protocol
    dissectors. However, it is strongly recommended that you upgrade to the
    latest stable version.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/ethereal-0.10.10"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0699');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0704');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0705');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0739');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0765');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0766');
script_set_attribute(attribute: 'see_also', value: 'http://www.ethereal.com/appnotes/enpa-sa-00018.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-16] Ethereal: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.10"), vulnerable: make_list("lt 0.10.10")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
