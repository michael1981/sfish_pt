# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-15.xml
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
 script_id(16002);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200412-15");
 script_cve_id("CVE-2004-1139", "CVE-2004-1140", "CVE-2004-1141", "CVE-2004-1142");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-15
(Ethereal: Multiple vulnerabilities)


    There are multiple vulnerabilities in versions of Ethereal earlier
    than 0.10.8, including:
    Bug in DICOM dissection
    discovered by Bing could make Ethereal crash (CAN 2004-1139).
    An invalid RTP timestamp could make Ethereal hang and create a
    large temporary file (CAN 2004-1140).
    The HTTP dissector could
    access previously-freed memory (CAN 2004-1141).
    Brian Caswell
    discovered that an improperly formatted SMB could make Ethereal hang
    (CAN 2004-1142).
  
Impact

    An attacker might be able to use these vulnerabilities to crash
    Ethereal, perform DoS by CPU and disk space utilization or even execute
    arbitrary code with the permissions of the user running Ethereal, which
    could be the root user.
  
Workaround

    For a temporary workaround you can disable all affected protocol
    dissectors by selecting Analyze->Enabled Protocols... and deselecting
    them from the list. However, it is strongly recommended to upgrade to
    the latest stable version.
  
');
script_set_attribute(attribute:'solution', value: '
    All ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/ethereal-0.10.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.ethereal.com/appnotes/enpa-sa-00016.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1139');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1140');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1141');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1142');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-15] Ethereal: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.8"), vulnerable: make_list("lt 0.10.8")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
