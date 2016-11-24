# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200808-06.xml
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
 script_id(33836);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200808-06");
 script_cve_id("CVE-2008-2935");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200808-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200808-06
(libxslt: Execution of arbitrary code)


    Chris Evans (Google Security) reported that the libexslt library that
    is part of libxslt is affected by a heap-based buffer overflow in the
    RC4 encryption/decryption functions.
  
Impact

    A remote attacker could entice a user to process an XML file using a
    specially crafted XSLT stylesheet in an application linked against
    libxslt, possibly leading to the execution of arbitrary code with the
    privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libxslt users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/libxslt-1.1.24-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2935');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200808-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200808-06] libxslt: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libxslt: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/libxslt", unaffected: make_list("ge 1.1.24-r1", "lt 1.1.8"), vulnerable: make_list("lt 1.1.24-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
