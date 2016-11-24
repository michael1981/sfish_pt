# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200808-07.xml
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
 script_id(33853);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200808-07");
 script_cve_id("CVE-2007-6595", "CVE-2008-2713", "CVE-2008-3215");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200808-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200808-07
(ClamAV: Multiple Denials of Service)


    Damian Put has discovered an out-of-bounds memory access while
    processing Petite files (CVE-2008-2713, CVE-2008-3215). Also, please
    note that the 0.93 ClamAV branch fixes the first of the two attack
    vectors of CVE-2007-6595 concerning an insecure creation of temporary
    files vulnerability. The sigtool attack vector seems still unfixed.
  
Impact

    A remote attacker could entice a user or automated system to scan a
    specially crafted Petite file, possibly resulting in a Denial of
    Service (daemon crash). Also, the insecure creation of temporary files
    vulnerability can be triggered by a local user to perform a symlink
    attack.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.93.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6595');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2713');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3215');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200808-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200808-07] ClamAV: Multiple Denials of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Multiple Denials of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.93.3"), vulnerable: make_list("lt 0.93.3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
