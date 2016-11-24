# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-16.xml
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
 script_id(18088);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200504-16");
 script_cve_id("CVE-2005-0753");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-16
(CVS: Multiple vulnerabilities)


    Alen Zukich has discovered several serious security issues in CVS,
    including at least one buffer overflow (CAN-2005-0753), memory leaks
    and a NULL pointer dereferencing error. Furthermore when launching
    trigger scripts CVS includes a user controlled directory.
  
Impact

    An attacker could exploit these vulnerabilities to cause a Denial of
    Service or execute arbitrary code with the permissions of the CVS
    pserver or the authenticated user (depending on the connection method
    used).
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All CVS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/cvs-1.11.20"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0753');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-16] CVS: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CVS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/cvs", unaffected: make_list("ge 1.11.20"), vulnerable: make_list("lt 1.11.20")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
