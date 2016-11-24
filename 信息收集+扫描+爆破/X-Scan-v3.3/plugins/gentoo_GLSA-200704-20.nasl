# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200704-20.xml
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
 script_id(25108);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200704-20");
 script_cve_id("CVE-2007-1543", "CVE-2007-1544", "CVE-2007-1545", "CVE-2007-1546", "CVE-2007-1547");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200704-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200704-20
(NAS: Multiple vulnerabilities)


    Luigi Auriemma has discovered multiple vulnerabilities in NAS, some of
    which include a buffer overflow in the function accept_att_local(), an
    integer overflow in the function ProcAuWriteElement(), and a null
    pointer error in the function ReadRequestFromClient().
  
Impact

    An attacker having access to the NAS daemon could send an overly long
    slave name to the server, leading to the execution of arbitrary code
    with root privileges. A remote attacker could also send a specially
    crafted packet containing an invalid client ID, which would crash the
    server and result in a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All NAS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/nas-1.8b"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1543');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1544');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1545');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1546');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1547');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200704-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200704-20] NAS: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'NAS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/nas", unaffected: make_list("ge 1.8b"), vulnerable: make_list("lt 1.8b")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
