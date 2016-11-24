# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-12.xml
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
 script_id(26102);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200709-12");
 script_cve_id("CVE-2007-3387");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-12
(Poppler: Two buffer overflow vulnerabilities)


    Poppler and Xpdf are vulnerable to an integer overflow in the
    StreamPredictor::StreamPredictor function, and a stack overflow in the
    StreamPredictor::getNextLine function. The original vulnerability was
    discovered by Maurycy Prodeus. Note: Gentoo\'s version of Xpdf is
    patched to use the Poppler library, so the update to Poppler will also
    fix Xpdf.
  
Impact

    By enticing a user to view a specially crafted program with a
    Poppler-based PDF viewer such as Gentoo\'s Xpdf, Epdfview, or Evince, a
    remote attacker could cause an overflow, potentially resulting in the
    execution of arbitrary code with the privileges of the user running the
    application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Poppler users should upgrade to the latest version of Poppler:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/poppler-0.5.4-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3387');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-12] Poppler: Two buffer overflow vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Poppler: Two buffer overflow vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/poppler", unaffected: make_list("ge 0.5.4-r2"), vulnerable: make_list("lt 0.5.4-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
